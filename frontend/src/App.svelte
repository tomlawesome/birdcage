<script lang="ts">
  // Issue #36: the chrome -- wordmark, tabs, range chips, status, the
  // sideways deck, the footer sentence slot, the "i" button. Issue #38
  // fills the status pill, the footer sentence and the hero/sub sentence
  // with the real rules (frontend/src/lib/sentence), and adds the tiles
  // and events that render below the chrome. Issue #39: this is the one
  // place that fetches -- the three reads together (Promise.all),
  // whenever activeRange changes and every 30 s -- and lib/loader.ts's
  // pure state machine decides loading/error/ready/stale from the
  // outcome; Band, Tiles and Events take their data as props and fetch
  // nothing themselves. Issue #56 adds the state history on the same
  // tick, alongside those three rather than inside their Promise.all --
  // see the `history` state below for why.
  //
  // Issue #118 adds the app's second page: one canary's own view, at
  // #/canaries/<id>. The chrome below is shared -- only <main> and the
  // footer sentence change -- and the page's own read joins the same
  // tick as the four above, so a canary page refreshes exactly as the
  // cage does.
  //
  // Issue #8 (slice B, ADR-0017): sign-in. The session is read before
  // anything else; until it says the account is in with nothing owed,
  // the door shows and no dashboard route is requested. A 401 from any
  // read later brings the door back -- over the dimmed dashboard when the
  // session can be resumed, the full sign-in otherwise.
  import { fetchCanaries, fetchCanary, fetchCanaryRuns, fetchHistory, fetchMail, fetchTrace, fetchVisitors, inFixtureMode, onSignedOut, sendJSON } from './lib/api'
  import { onMount, tick } from 'svelte'
  import { doorFor, readSession, type SessionState } from './lib/auth'
  import Door from './door/Door.svelte'
  import type { CanaryPageResponse, HistoryResponse, MailStatus, RunsResponse } from './lib/types'
  import { computeFooter, computeSentence, computeStatus, formatClock, mailLine } from './lib/sentence'
  import { isSameUTCDate } from './lib/sentence/time'
  import { initialLoaderState, onFetchError, onFetchSuccess, type LoaderState } from './lib/loader'
  import { cageHref, parseRoute, type Route } from './lib/route'
  import { canaryFooter } from './lib/canary/sentence'
  import Band from './lib/band/Band.svelte'
  import Tiles from './Tiles.svelte'
  import Events from './Events.svelte'
  import History from './History.svelte'
  import CanaryPage from './CanaryPage.svelte'

  const RANGES = ['15m', '1h', '24h', '14d', '90d'] as const
  type RangeKey = (typeof RANGES)[number]
  const RANGE_LABELS: Record<RangeKey, string> = {
    '15m': '15 m',
    '1h': '1 h',
    '24h': '24 h',
    '14d': '14 d',
    '90d': '90 d',
  }
  let activeRange: RangeKey = $state('14d')

  const TABS = ['the cage', 'visitors', 'audit log']
  let activeTab = $state(0)

  const DECK = ['THE TRACE', 'VISITORS', 'AUDIT LOG', 'SETTINGS']
  let activeDeck = $state(0)

  const REFRESH_MS = 30_000

  // 'start' until the first session read lands; 'in' while the dashboard
  // is allowed to fetch; 'checking' while a 401 is being read back (the
  // dashboard stays drawn, nothing is fetched); 'door' while the door shows.
  let phase = $state<'start' | 'in' | 'checking' | 'door'>('start')
  let session = $state<SessionState | null>(null)
  // The account name this tab had, for the expired screen: gauntlet does
  // not send it once the session has timed out.
  let knownName: string | undefined = undefined
  // The door opening onto the dashboard (ADR-0017 decision 2).
  let leaving = $state(false)

  const SIGNED_OUT: SessionState = {
    setupRequired: false,
    ssoAvailable: false,
    authenticated: false,
    hasLocalPassword: false,
    ssoConnected: false,
    mustChangePassword: false,
    mustEnrolSecondFactor: false,
    mustEnrolPasskey: false,
    hasTOTP: false,
  }

  /** Show what the session names: the dashboard, or the door. */
  function arrive(s: SessionState) {
    if (s.username) knownName = s.username
    session = { ...s, username: s.username ?? knownName }
    if (doorFor(s) === 'in') phase = 'in'
    else {
      phase = 'door'
      forgetDashboard()
    }
  }

  // Bumped whenever the door shows: a dashboard reply that left before it
  // carries the old number and is dropped, so nothing of the session the
  // door replaced is drawn again behind it.
  let epoch = 0

  /** Nothing of the last session's dashboard stays in memory. */
  function forgetDashboard() {
    epoch++
    loaderState = initialLoaderState
    history = null
    historyFailed = false
    mail = null
    canaryPage = null
    canaryFailed = false
    canaryRuns = null
  }

  async function check() {
    try {
      arrive(await readSession())
    } catch {
      // No answer at all: the sign-in, which says so if it fails too.
      arrive(SIGNED_OUT)
    }
  }

  onMount(() =>
    onSignedOut(() => {
      if (phase !== 'in') return
      phase = 'checking'
      void check()
    }),
  )
  void check()

  const stillMotion = () => typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches

  /** The door says the account is in: open it onto the dashboard (the
   * last session's data went when the door showed). */
  function enter(s: SessionState) {
    arrive(s)
    if (stillMotion()) return
    leaving = true
    // The bars slide apart over 700 ms and the door fades with them.
    setTimeout(() => (leaving = false), 750)
  }

  // The name chip's menu (owner 28a, docs/design/sign-in-screens.md,
  // "Sign-out"): one item, Sign out. A failed request keeps the menu open
  // with its alert; a click while one is in flight sends nothing.
  let menuOpen = $state(false)
  let signingOut = $state(false)
  let signOutFailed = $state(false)
  let chipEl: HTMLButtonElement | undefined = $state()
  let menuBox: HTMLElement | undefined = $state()
  let signOutEl: HTMLButtonElement | undefined = $state()

  async function openMenu() {
    menuOpen = true
    signOutFailed = false
    await tick()
    signOutEl?.focus()
  }
  function closeMenu() {
    menuOpen = false
    signOutFailed = false
    chipEl?.focus()
  }
  const toggleMenu = () => (menuOpen ? closeMenu() : void openMenu())

  // A click (or touch) anywhere outside the chip and its menu closes it.
  $effect(() => {
    if (!menuOpen) return
    const outside = (e: Event) => {
      if (menuBox && e.target instanceof Node && menuBox.contains(e.target)) return
      closeMenu()
    }
    document.addEventListener('pointerdown', outside)
    document.addEventListener('mousedown', outside)
    return () => {
      document.removeEventListener('pointerdown', outside)
      document.removeEventListener('mousedown', outside)
    }
  })

  async function signOut() {
    if (signingOut) return
    signingOut = true
    signOutFailed = false
    try {
      await sendJSON('POST', '/api/auth/logout')
    } catch {
      signOutFailed = true
      return
    } finally {
      signingOut = false
    }
    menuOpen = false
    // Whoever signs in next is someone new to this tab.
    knownName = undefined
    arrive({ ...SIGNED_OUT, ssoAvailable: session?.ssoAvailable ?? false })
  }

  let doorShown = $derived(phase === 'door' || leaving)
  let shellShown = $derived(phase === 'in' || phase === 'checking' || (phase === 'door' && session !== null && doorFor(session) === 'expired'))

  // The whole router (lib/route.ts): which of the app's two places is
  // showing. Read once at mount and re-read on every hashchange, so the
  // back button, a bookmark and a typed address all work without any
  // history bookkeeping of our own.
  let route: Route = $state(typeof location === 'undefined' ? { name: 'cage' } : parseRoute(location.hash))
  $effect(() => {
    if (typeof window === 'undefined') return
    const onHashChange = () => (route = parseRoute(location.hash))
    window.addEventListener('hashchange', onHashChange)
    return () => window.removeEventListener('hashchange', onHashChange)
  })

  // Issue #118's read, on the same tick as the four below and kept out
  // of the Promise.all for the same reason the history is: it answers
  // for one page, and a canary that has just been deleted should say so
  // on its own page rather than stale the whole shell.
  let canaryPage: CanaryPageResponse | null = $state(null)
  let canaryFailed = $state(false)

  // ADR-0012 (issue #116): a scanner's own scan-run history, fetched on
  // the same tick as the canary page's own read and for the same
  // reason -- it is one section of that page, not the page, so a failed
  // read simply leaves the section with nothing to say rather than
  // staling the rest of the page. Never fetched off the fleet page: it
  // is per-canary, like the page read itself.
  let canaryRuns: RunsResponse | null = $state(null)

  let loaderState: LoaderState = $state(initialLoaderState)

  // Issue #56's fourth read. Kept out of the Promise.all below on
  // purpose: the state history is a section of the page, not the page,
  // so a history outage draws its own line and leaves the tiles, the
  // band and the events exactly as they were -- where a failed canaries
  // or trace read still stales the whole dashboard, because nothing on
  // it would be true without them.
  let history: HistoryResponse | null = $state(null)
  let historyFailed = $state(false)

  // Issue #55's fifth read, on the same refresh and kept out of the
  // Promise.all for the same reason the history is: the mail line is
  // one item in the status strip, so a failed /api/mail read drops that
  // item and leaves the whole rest of the page exactly as it was. A
  // read that has never succeeded leaves this null, and the strip
  // simply has one fewer item rather than claiming a state it does not
  // know yet.
  let mail: MailStatus | null = $state(null)

  // triggerRefresh always points at the current effect run's `load`
  // below, so issue #44's stream subscription can ask for an immediate
  // refetch without duplicating the range/in-flight logic that effect
  // already owns. null only before the first effect run, which never
  // overlaps with the stream effect actually receiving a message.
  let triggerRefresh: (() => void) | null = null

  // Refetches whenever activeRange changes and every REFRESH_MS after
  // that; `inFlight` is local to this effect run (a fresh false every
  // time activeRange changes) so switching ranges never waits on a
  // slow fetch for the *previous* range, while a tick that lands on top
  // of a still-pending fetch for the *current* range is simply skipped
  // rather than doubled. A response that arrives after activeRange has
  // since moved on is dropped, not applied. This poll is issue #44's
  // required fallback: it stays exactly as it was before that issue,
  // so a stream that never connects, drops, or is disabled leaves the
  // dashboard behaving exactly as it does today.
  $effect(() => {
    // Nothing is fetched while the door is (or may be) showing.
    if (phase !== 'in') return
    const range = activeRange
    // Read here so the effect re-subscribes on navigation: moving to a
    // canary page must fetch that page now, not on the next 30 s tick.
    const currentRoute = route
    // A reply is applied only while its range is still the one showing
    // and the door has not shown since it left (epoch).
    const gen = epoch
    const current = () => range === activeRange && gen === epoch
    let inFlight = false
    const load = async () => {
      if (inFlight) return
      inFlight = true
      // Same tick, same in-flight guard and the same "drop a response for
      // a range we've since left" check as the three reads below, so the
      // history section refreshes on the poll and on a pushed event
      // exactly as the rest of the page does.
      // Narrowed to one canary on its own page: the section there is a
      // thread of that canary's states, not the fleet's.
      const historyCanary = currentRoute.name === 'canary' ? currentRoute.id : undefined
      const historyLoad = fetchHistory(range, historyCanary)
        .then((h) => {
          if (!current()) return
          history = h
          historyFailed = false
        })
        .catch(() => {
          if (current()) historyFailed = true
        })
      const canaryLoad =
        currentRoute.name === 'canary'
          ? fetchCanary(currentRoute.id, range)
              .then((p) => {
                if (!current()) return
                canaryPage = p
                canaryFailed = false
              })
              .catch(() => {
                if (current()) {
                  canaryPage = null
                  canaryFailed = true
                }
              })
          : Promise.resolve()
      // ADR-0012 (issue #116): kept out of canaryLoad's own catch on
      // purpose -- a failed runs read should not blank the rest of the
      // canary page, the same reasoning historyLoad already follows.
      const runsLoad =
        currentRoute.name === 'canary'
          ? fetchCanaryRuns(currentRoute.id)
              .then((r) => {
                if (current()) canaryRuns = r
              })
              .catch(() => {
                if (current()) canaryRuns = null
              })
          : Promise.resolve().then(() => {
              if (gen === epoch) canaryRuns = null
            })
      // Same tick, same "drop a response for a range we've since left"
      // check. Range-free itself -- "is mail working" is not a question
      // about a window -- but still guarded, so a slow response landing
      // after the operator changed range cannot overwrite a newer one.
      const mailLoad = fetchMail()
        .then((m) => {
          if (current()) mail = m
        })
        .catch(() => {
          // Leave whatever was last known in place: one failed poll is
          // not evidence about the mailer, and the strip going blank
          // every time a poll blips would be noise.
        })
      try {
        const [c, v, t] = await Promise.all([fetchCanaries(range), fetchVisitors(range), fetchTrace(range)])
        if (current()) loaderState = onFetchSuccess({ canaries: c.canaries, visitors: v.visitors, trace: t })
      } catch {
        if (current()) loaderState = onFetchError(loaderState)
      } finally {
        await historyLoad
        await mailLoad
        await canaryLoad
        await runsLoad
        inFlight = false
      }
    }
    triggerRefresh = load
    load()
    const interval = setInterval(load, REFRESH_MS)
    return () => clearInterval(interval)
  })

  // Issue #44: birdcage pushes a server-sent event whenever an alert is
  // stored, so an already-open dashboard sees it within a second instead
  // of waiting for the poll above. The event merely triggers the same
  // refetch the poll already does (triggerRefresh, reusing its in-flight
  // guard and its "drop a response for a range we've since left" check)
  // rather than hand-parsing the pushed alert into loaderState itself --
  // one loader, one source of truth for what the page shows, whether the
  // fetch was requested by the clock or by a push.
  //
  // The connection is independent of activeRange -- a live hit should
  // refresh whichever range is showing -- and is left to the browser's
  // own EventSource reconnect logic (no custom retry code, per the
  // ratified approach): if the stream drops, the poll above keeps the
  // page correct until EventSource reconnects on its own. A browser
  // without EventSource, or a stream that never connects at all, simply
  // never calls triggerRefresh here -- the dashboard behaves exactly as
  // it did before this effect existed.
  $effect(() => {
    if (phase !== 'in') return
    if (typeof EventSource === 'undefined') return
    // A fixture scene has no server behind it: the fetches above already
    // answer from the fixture, and the stream must stay closed too.
    if (inFixtureMode()) return
    const source = new EventSource('/api/stream')
    source.onmessage = () => triggerRefresh?.()
    return () => source.close()
  })

  let data = $derived(loaderState.data)
  let canaries = $derived(data?.canaries ?? [])
  let visitors = $derived(data?.visitors ?? [])
  let trace = $derived(data?.trace ?? null)

  let status = $derived(data ? computeStatus(canaries, visitors, activeRange) : null)
  let sentence = $derived(
    data && trace ? computeSentence(canaries, visitors, activeRange, trace.now, trace.last_hit) : null,
  )
  // The footer speaks for whichever page is showing: the cage's summary,
  // or this canary's own closing line.
  let footer = $derived(
    !data || !trace
      ? null
      : route.name === 'canary'
        ? canaryPage
          ? canaryFooter({ page: canaryPage, trace, visitors, history })
          : null
        : computeFooter(canaries, visitors, activeRange, trace.now, trace.last_hit),
  )

  // The strip's mail item (issue #55). Measured against trace.now, the
  // same clock every other duration on this page uses, so a fixture
  // scene reads the same as a live fleet. Null until both reads have
  // landed -- there is no useful "mail ok · last ? ago".
  let mailStatus = $derived(trace ? mailLine(mail, trace.now) : null)

  const WEEKDAYS = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat']
  const MONTHS = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec']

  /** "the cage · sat 5 sep · 22:04:31" (quiet/silent) or "the cage · fri
   * 12 sep · 1 flagged · N hits today" (live) -- gen.py's `.grp` line
   * above the hero. N counts trace.canaries[].hits whose `at` falls on
   * the same UTC calendar day as trace.now (issue #39) -- Canary.hits
   * is a range total, not "today". */
  let grpLine = $derived.by(() => {
    if (!trace) return { lead: '', flagged: '', tail: '' }
    const d = new Date(trace.now)
    const day = `${WEEKDAYS[d.getUTCDay()]} ${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]}`
    if (status?.kind === 'live') {
      const hitsToday = trace.canaries.reduce(
        (sum, c) => sum + c.hits.filter((h) => isSameUTCDate(h.at, trace.now)).length,
        0,
      )
      return { lead: `the cage · ${day} · `, flagged: `${status.flagCount} flagged`, tail: ` · ${hitsToday} hits today` }
    }
    return { lead: `the cage · ${day} · ${formatClock(trace.now)}`, flagged: '', tail: '' }
  })
</script>

{#if shellShown}
<div class="scene">
  <div class="wordmark" aria-label="Birdcage">BIRD<em>CAGE</em></div>

  <nav class="tabs" aria-label="Sections">
    {#each TABS as tab, i (tab)}
      <button
        type="button"
        class:on={i === activeTab && route.name === 'cage'}
        aria-current={i === activeTab && route.name === 'cage'}
        onclick={() => {
          activeTab = i
          // The cage tab is also the way back from a canary page.
          if (i === 0 && route.name === 'canary') location.hash = cageHref
        }}
      >
        {tab}
      </button>
      <!-- The crumb sits directly after "the cage", the way the concept
           puts it: this page is a place inside that tab, not a fifth
           tab of its own. -->
      {#if i === 0 && route.name === 'canary'}
        <span class="crumb">&rsaquo; <b>{route.id}</b></span>
      {/if}
    {/each}
  </nav>

  <div class="status" aria-label="Status" role="status">
    <div class="ranges" role="group" aria-label="Time range">
      {#each RANGES as range (range)}
        <button
          type="button"
          class:on={range === activeRange}
          aria-pressed={range === activeRange}
          onclick={() => (activeRange = range)}
        >
          {RANGE_LABELS[range]}
        </button>
      {/each}
    </div>
    {#if status === null}
      <span class="dim">no data yet</span>
    {:else if status.kind === 'silent'}
      <span
        ><span class="dot off" aria-hidden="true"></span>{status.okCount} of {status.total} phoning home &middot;
        <span class="mute">{status.silentName} silent {status.silentFor}</span></span
      >
      <span>&#9678; {status.visitorCount} visitors &middot; {RANGE_LABELS[activeRange]}</span>
    {:else if status.kind === 'critical'}
      <span
        ><span class="dot off" aria-hidden="true"></span>{status.okCount} of {status.total} phoning home &middot;
        <span class="crit">{status.label}</span></span
      >
      <span>&#9678; {status.visitorCount} visitors &middot; {RANGE_LABELS[activeRange]}</span>
    {:else if status.kind === 'degraded'}
      <span
        ><span class="dot off" aria-hidden="true"></span>{status.okCount} of {status.total} phoning home &middot;
        <span class="degr">{status.label}</span></span
      >
      <span>&#9678; {status.visitorCount} visitors &middot; {RANGE_LABELS[activeRange]}</span>
    {:else if status.kind === 'live'}
      <span><span class="dot" aria-hidden="true"></span>LIVE &middot; {status.total} agents</span>
      {#if status.flagCount > 0}<span class="flag">&#9873; <b>{status.flagCount}</b></span>{/if}
      <span>&#9678; {status.visitorCount} visitors</span>
    {:else}
      <span><span class="dot" aria-hidden="true"></span>QUIET &middot; {status.okCount} of {status.total} phoning home</span>
      <span>&#9678; {status.visitorCount} visitors &middot; {RANGE_LABELS[activeRange]}</span>
    {/if}
    <!-- issue #55: after the visitors count, in the strip's own voice
         and its existing classes -- muted for "off" and "ok", the alarm
         class only when mail has actually stopped working, since
         nothing else on this page would go red about that. -->
    {#if mailStatus}<span class={mailStatus.cls} title={mailStatus.detail}>{mailStatus.text}</span>{/if}
    <!-- The signed-in account, and under it the sign-out menu: only while
         signed in (behind the expired door there is no role to show). -->
    {#if session?.authenticated && session.username}
      <span class="who-box" bind:this={menuBox}>
        <button
          type="button"
          class="who"
          bind:this={chipEl}
          aria-haspopup="menu"
          aria-expanded={menuOpen}
          onclick={toggleMenu}>{session.username} ({session.role})</button
        >
        {#if menuOpen}
          <div class="menu" role="menu" tabindex="-1" onkeydown={(e) => e.key === 'Escape' && (e.preventDefault(), closeMenu())}>
            <button type="button" role="menuitem" bind:this={signOutEl} onclick={signOut}>Sign out</button>
            {#if signOutFailed}<p class="menu-error" role="alert">Could not sign out. Try again.</p>{/if}
          </div>
        {/if}
      </span>
    {/if}
  </div>

  <nav class="deck" aria-label="Views">
    {#each DECK as item, i (item)}
      <button type="button" class:on={i === activeDeck} aria-current={i === activeDeck} onclick={() => (activeDeck = i)}>
        {item}
      </button>
    {/each}
  </nav>

  <main aria-label={route.name === 'canary' ? route.id : TABS[activeTab]}>
    <!-- The sentence (#38), the band (#37), the tiles and the events
         (#38) -- but only once the first fetch has landed (issue #39):
         no data yet draws only this state line, in the concept's voice,
         at the hero sentence's position. -->
    {#if !data}
      <div class="state-line">{#if loaderState.phase === 'error'}the cage is not answering &middot; retrying in 30 s{:else}listening for the cage&hellip;{/if}</div>
    {:else if route.name === 'canary'}
      <!-- Issue #118: one canary's own page. The shell above is
           unchanged; only what fills main is. -->
      {#if canaryPage && trace}
        <CanaryPage page={canaryPage} {trace} {visitors} {history} runs={canaryRuns} range={activeRange} />
      {:else}
        <div class="state-line">
          {#if canaryFailed}there is no agent called {route.id} &middot; <a href={cageHref}>back to the cage</a>{:else}listening
            for {route.id}&hellip;{/if}
        </div>
      {/if}
    {:else if sentence && trace}
      <div class="grp">{grpLine.lead}{#if grpLine.flagged}<span class="r">{grpLine.flagged}</span>{grpLine.tail}{/if}</div>
      <div class="hero">
        {#each sentence.hero as seg, i (i)}{#if seg.bold}<b class={seg.cls}>{seg.text}</b
          >{:else}<span class={seg.cls}>{seg.text}</span>{/if}{/each}
      </div>
      <div class="sub">
        {#each sentence.sub as seg, i (i)}{#if seg.bold}<b class={seg.cls}>{seg.text}</b
          >{:else}<span class={seg.cls}>{seg.text}</span>{/if}{/each}
      </div>
      <Band {trace} />
      <Tiles {canaries} {trace} range={activeRange} />
      <History {history} failed={historyFailed} range={activeRange} />
      <Events {canaries} {visitors} {trace} range={activeRange} />
    {/if}
  </main>

  <footer class="foot" aria-label="Summary">
    {#if data && loaderState.phase === 'stale'}
      <span>the cage is not answering</span>
    {:else if footer}
      <!-- One span, like gen.py: .foot is a flex row, and flex items drop
           the spaces between the segments. -->
      <span
        >{#each footer as seg, i (i)}{#if seg.bold}<b class={seg.cls}>{seg.text}</b
          >{:else}<span class={seg.cls}>{seg.text}</span>{/if}{/each}</span
      >
    {/if}
  </footer>

  <button type="button" class="ibtn" aria-label="About birdcage">i</button>
</div>
{/if}

{#if doorShown && session}
  <Door {session} onenter={enter} {leaving} />
{/if}

<style>
  .scene {
    position: relative;
    min-height: 100vh;
  }

  .wordmark {
    position: absolute;
    top: 18px;
    left: 24px;
    font-weight: 800;
    font-size: 15px;
    letter-spacing: 0.04em;
  }
  .wordmark em {
    font-style: normal;
    color: var(--accent);
  }

  .tabs {
    position: absolute;
    top: 21px;
    left: 150px;
    display: flex;
    gap: 20px;
    font: 12px var(--sans);
  }
  .tabs button {
    background: none;
    border: none;
    padding: 0;
    color: var(--ink-3);
    font: inherit;
  }
  .tabs button.on {
    color: var(--ink);
    position: relative;
  }
  .tabs .crumb {
    color: var(--ink-3);
    align-self: center;
  }
  .tabs .crumb b {
    color: var(--iot);
    font: 700 12px var(--mono);
  }
  .tabs button.on::after {
    content: '';
    position: absolute;
    left: 0;
    right: 0;
    bottom: -4px;
    height: 1px;
    background: var(--accent);
  }

  .status {
    position: absolute;
    top: 20px;
    right: 40px;
    display: flex;
    gap: 16px;
    align-items: center;
    font: 11px var(--mono);
    color: var(--ink-2);
  }
  .status .dim {
    color: var(--ink-3);
  }
  .status .dot {
    display: inline-block;
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--ok);
    margin-right: 5px;
    vertical-align: 1px;
  }
  .status .dot.off {
    background: none;
    border: 1.5px solid var(--ink-2);
  }
  @media (prefers-reduced-motion: no-preference) {
    .status .dot {
      animation: pulse 1.8s ease-in-out infinite;
    }
    .status .dot.off {
      animation: none;
    }
    @keyframes pulse {
      50% {
        opacity: 0.4;
      }
    }
  }
  .status .flag {
    color: var(--alarm);
  }
  .status .flag b {
    color: var(--void);
    background: var(--alarm);
    border-radius: 9px;
    padding: 0 7px;
    font-weight: 700;
    font-size: 10.5px;
  }
  .status .mute {
    color: var(--ink);
    font-weight: 700;
  }
  /* issue #45's critical/degraded pill text, alongside .mute (silent)
     and .flag (an active sweep). */
  .status .crit {
    color: var(--alarm);
    font-weight: 700;
  }
  .status .degr {
    color: var(--repeat);
    font-weight: 700;
  }
  .status .who-box {
    position: relative;
  }
  .status .who {
    color: var(--ink-3);
    background: none;
    border: 1px solid var(--hair-2);
    border-radius: 999px;
    padding: 2px 10px;
    font: inherit;
    cursor: pointer;
  }
  /* The sign-out menu: under the chip, right-aligned, in the shell's
     tokens and the chip's own type. */
  .status .menu {
    position: absolute;
    top: calc(100% + 6px);
    right: 0;
    z-index: 10;
    min-width: 100%;
    background: var(--raised);
    border: 1px solid var(--hair-2);
    border-radius: 6px;
    padding: 4px;
    font: inherit;
    white-space: nowrap;
  }
  .status .menu button {
    display: block;
    width: 100%;
    text-align: left;
    background: none;
    border: none;
    border-radius: 4px;
    padding: 4px 8px;
    color: var(--ink-2);
    font: inherit;
    cursor: pointer;
  }
  .status .menu button:hover,
  .status .menu button:focus-visible {
    color: var(--ink);
    background: var(--hair-2);
    outline: none;
  }
  .status .menu-error {
    margin: 4px 8px 2px;
    color: var(--ink-3);
  }

  .ranges {
    display: flex;
    gap: 4px;
    margin-right: 8px;
  }
  .ranges button {
    background: none;
    border: none;
    font: 11px var(--mono);
    color: var(--ink-3);
    padding: 2px 9px;
    border-radius: 4px;
  }
  .ranges button.on {
    color: var(--ink);
    background: var(--raised);
    border: 1px solid var(--hair-2);
  }

  .deck {
    position: absolute;
    right: 8px;
    top: 50%;
    transform: translateY(-50%);
    display: flex;
    flex-direction: column;
    gap: 30px;
    align-items: center;
  }
  .deck button {
    background: none;
    border: none;
    writing-mode: sideways-lr;
    color: var(--ink-3);
    font: 500 9.5px var(--mono);
    letter-spacing: 0.22em;
  }
  .deck button.on {
    color: var(--ink);
    font-size: 12px;
    letter-spacing: 0.26em;
  }

  main {
    padding-top: 60px;
    min-height: calc(100vh - 60px - 40px);
  }

  /* The sentence (issue #38): positioned like gen.py's .grp/.hero/.sub,
     absolute within .scene -- same coordinate system as the wordmark and
     status above, so source order here doesn't have to match the band's. */
  .grp {
    position: absolute;
    left: 54px;
    top: 70px;
    font: 600 9.5px var(--mono);
    letter-spacing: 0.16em;
    color: var(--ink-3);
    text-transform: uppercase;
  }
  .grp .r {
    color: var(--alarm);
  }
  .hero {
    position: absolute;
    left: 54px;
    top: 94px;
    font: 500 26px/1.2 var(--sans);
    color: var(--ink);
    letter-spacing: -0.01em;
  }
  .hero :global(b) {
    font-weight: 700;
  }
  .sub {
    position: absolute;
    left: 54px;
    top: 134px;
    width: 900px;
    font: 13px/1.55 var(--sans);
    color: var(--ink-2);
  }
  .sub :global(b) {
    color: var(--ink);
    font-weight: 600;
  }
  .hero :global(.ok),
  .sub :global(.ok),
  .foot :global(.ok) {
    color: var(--ok);
  }
  .hero :global(.r),
  .sub :global(.r),
  .foot :global(.r) {
    color: var(--alarm);
  }
  .sub :global(.ip),
  .foot :global(.ip) {
    font: 12.5px var(--mono);
    color: var(--ink);
  }

  /* Loading/error, issue #39: the hero sentence's own position, but the
     .sub font/colour -- one line, never a spinner, and nothing else on
     the page (no band/tiles/events/footer) until the first fetch lands. */
  .state-line {
    position: absolute;
    left: 54px;
    top: 94px;
    font: 13px/1.55 var(--sans);
    color: var(--ink-2);
  }
  .state-line a {
    color: var(--accent);
  }

  .foot {
    position: absolute;
    left: 0;
    right: 40px;
    bottom: 14px;
    display: flex;
    justify-content: center;
    font: 12.5px var(--sans);
    color: var(--ink-2);
  }
  .foot :global(b) {
    color: var(--ink);
    font-weight: 600;
  }

  .ibtn {
    position: absolute;
    left: 14px;
    bottom: 12px;
    width: 18px;
    height: 18px;
    border-radius: 50%;
    border: 1px solid var(--hair-2);
    background: none;
    color: var(--ink-3);
    font: italic 600 11px Georgia, serif;
    text-align: center;
    line-height: 16px;
    padding: 0;
  }
</style>
