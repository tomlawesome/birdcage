<script lang="ts">
  // Issue #36: the chrome -- wordmark, tabs, range chips, status, the
  // sideways deck, the footer sentence slot, the "i" button. Issue #38
  // fills the status pill, the footer sentence and the hero/sub sentence
  // with the real rules (frontend/src/lib/sentence), and adds the tiles
  // and events that render below the chrome.
  import { fetchCanaries, fetchTrace, fetchVisitors } from './lib/api'
  import type { Canary, Visitor } from './lib/types'
  import { computeFooter, computeSentence, computeStatus, formatClock } from './lib/sentence'
  import Band from './lib/band/Band.svelte'
  import Tiles from './Tiles.svelte'
  import Events from './Events.svelte'

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

  let canaries: Canary[] = $state([])
  let visitors: Visitor[] = $state([])
  let traceNow: string | null = $state(null)
  let loaded = $state(false)

  // Reloads whenever activeRange changes -- the status pill, the
  // sentence, the footer and (each independently) Tiles and Events all
  // depend on the selected range. A failure here (no backend yet, or a
  // ?scene= that doesn't match a fixture) leaves loaded false and the
  // status slot renders its neutral state.
  $effect(() => {
    const range = activeRange
    ;(async () => {
      try {
        const [c, v, t] = await Promise.all([fetchCanaries(range), fetchVisitors(range), fetchTrace(range)])
        canaries = c.canaries
        visitors = v.visitors
        traceNow = t.now
        loaded = true
      } catch {
        loaded = false
      }
    })()
  })

  let status = $derived(loaded ? computeStatus(canaries, visitors, activeRange) : null)
  let sentence = $derived(loaded && traceNow ? computeSentence(canaries, visitors, activeRange, traceNow) : null)
  let footer = $derived(loaded && traceNow ? computeFooter(canaries, visitors, activeRange, traceNow) : null)

  const WEEKDAYS = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat']
  const MONTHS = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec']

  /** "the cage · sat 5 sep · 22:04:31" (quiet/silent) or "the cage · fri
   * 12 sep · 1 flagged · N hits" (live) -- gen.py's `.grp` line above the
   * hero. Not itself named in issue #38's acceptance list; approximated
   * from what fetchCanaries/fetchTrace carry (total hits in range, not
   * "today" specifically, since no field distinguishes the two). */
  let grpLine = $derived.by(() => {
    if (!traceNow) return { lead: '', flagged: '', tail: '' }
    const d = new Date(traceNow)
    const day = `${WEEKDAYS[d.getUTCDay()]} ${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]}`
    if (status?.kind === 'live') {
      const hits = canaries.reduce((sum, c) => sum + c.hits, 0)
      return { lead: `the cage · ${day} · `, flagged: `${status.flagCount} flagged`, tail: ` · ${hits} hits` }
    }
    return { lead: `the cage · ${day} · ${formatClock(traceNow)}`, flagged: '', tail: '' }
  })
</script>

<div class="scene">
  <div class="wordmark" aria-label="Birdcage">BIRD<em>CAGE</em></div>

  <nav class="tabs" aria-label="Sections">
    {#each TABS as tab, i (tab)}
      <button type="button" class:on={i === activeTab} aria-current={i === activeTab} onclick={() => (activeTab = i)}>
        {tab}
      </button>
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
    {:else if status.kind === 'live'}
      <span><span class="dot" aria-hidden="true"></span>LIVE &middot; {status.total} canaries</span>
      {#if status.flagCount > 0}<span class="flag">&#9873; <b>{status.flagCount}</b></span>{/if}
      <span>&#9678; {status.visitorCount} visitors</span>
    {:else}
      <span><span class="dot" aria-hidden="true"></span>QUIET &middot; {status.okCount} of {status.total} phoning home</span>
      <span>&#9678; {status.visitorCount} visitors &middot; {RANGE_LABELS[activeRange]}</span>
    {/if}
    <span class="who">tom (admin)</span>
  </div>

  <nav class="deck" aria-label="Views">
    {#each DECK as item, i (item)}
      <button type="button" class:on={i === activeDeck} aria-current={i === activeDeck} onclick={() => (activeDeck = i)}>
        {item}
      </button>
    {/each}
  </nav>

  <main aria-label={TABS[activeTab]}>
    <!-- The sentence (#38), the band (#37), the tiles and the events (#38). -->
    {#if sentence}
      <div class="grp">{grpLine.lead}{#if grpLine.flagged}<span class="r">{grpLine.flagged}</span>{grpLine.tail}{/if}</div>
      <div class="hero">
        {#each sentence.hero as seg, i (i)}{#if seg.bold}<b class={seg.cls}>{seg.text}</b
          >{:else}<span class={seg.cls}>{seg.text}</span>{/if}{/each}
      </div>
      <div class="sub">
        {#each sentence.sub as seg, i (i)}{#if seg.bold}<b class={seg.cls}>{seg.text}</b
          >{:else}<span class={seg.cls}>{seg.text}</span>{/if}{/each}
      </div>
    {/if}
    <Band range={activeRange} />
    <Tiles range={activeRange} />
    <Events range={activeRange} />
  </main>

  <footer class="foot" aria-label="Summary">
    {#if footer}
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
  .status .who {
    color: var(--ink-3);
    border: 1px solid var(--hair-2);
    border-radius: 999px;
    padding: 2px 10px;
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
