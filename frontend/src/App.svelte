<script lang="ts">
  // Issue #36: the chrome only -- wordmark, tabs, range chips, status,
  // the sideways deck, the footer sentence slot, the "i" button. The
  // band, the tiles and the events (the void below the chrome) are
  // later slices; this component leaves that area empty on purpose.
  import { fetchCanaries, fetchVisitors } from './lib/api'
  import type { Canary, Visitor } from './lib/types'

  const RANGES = ['15m', '1h', '24h', '14d', '90d'] as const
  type RangeKey = (typeof RANGES)[number]
  const RANGE_LABELS: Record<RangeKey, string> = {
    '15m': '15 m',
    '1h': '1 h',
    '24h': '24 h',
    '14d': '14 d',
    '90d': '90 d',
  }
  // Client state only (issue #36 scope): picking a range does not
  // refetch anything yet -- there is nothing below the chrome to
  // refresh until the band/tiles/events slices land.
  let activeRange: RangeKey = $state('14d')

  const TABS = ['the cage', 'visitors', 'audit log']
  let activeTab = $state(0)

  const DECK = ['THE TRACE', 'VISITORS', 'AUDIT LOG', 'SETTINGS']
  let activeDeck = $state(0)

  interface Summary {
    kind: 'quiet' | 'silent' | 'live'
    okCount: number
    total: number
    visitorCount: number
    note: string | null
    footSentence: string
  }

  let summary: Summary | null = $state(null)

  function formatDuration(seconds: number): string {
    const m = Math.floor(seconds / 60)
    const s = seconds % 60
    return m > 0 ? `${m} m ${s} s` : `${s} s`
  }

  function summarize(canaries: Canary[], visitors: Visitor[]): Summary {
    const okCount = canaries.filter((c) => c.status === 'ok').length
    const silent = canaries.find((c) => c.status === 'silent')
    const total = canaries.length
    const visitorCount = visitors.length

    if (silent) {
      return {
        kind: 'silent',
        okCount,
        total,
        visitorCount,
        note: `${silent.name} silent ${formatDuration(silent.silent_for_s ?? 0)}`,
        footSentence: 'silence is only good news while the heartbeat keeps coming',
      }
    }
    if (visitorCount > 0) {
      const flagged = visitors.filter((v) => v.kind === 'sweep').length
      return {
        kind: 'live',
        okCount,
        total,
        visitorCount,
        note: flagged > 0 ? `${flagged} flagged` : null,
        footSentence: 'one or more addresses have touched a canary in this range',
      }
    }
    return {
      kind: 'quiet',
      okCount,
      total,
      visitorCount,
      note: null,
      footSentence: 'a flat trace is the cage working -- nothing to act on',
    }
  }

  // Runs once when the component is created, deliberately not tied to
  // activeRange -- see the comment on activeRange above. A failure here
  // (no backend yet, or a scene param that doesn't match a fixture)
  // leaves summary null and the status slot renders its neutral state.
  ;(async () => {
    try {
      const [canaries, visitors] = await Promise.all([fetchCanaries('14d'), fetchVisitors('14d')])
      summary = summarize(canaries.canaries, visitors.visitors)
    } catch {
      summary = null
    }
  })()
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
    {#if summary === null}
      <span class="dim">no data yet</span>
    {:else if summary.kind === 'silent'}
      <span><span class="dot off" aria-hidden="true"></span>{summary.okCount} of {summary.total} phoning home<span class="mute"> · {summary.note}</span></span>
      <span>&#9678; {summary.visitorCount} visitors &middot; {RANGE_LABELS[activeRange]}</span>
    {:else if summary.kind === 'live'}
      <span><span class="dot" aria-hidden="true"></span>LIVE &middot; {summary.total} canaries</span>
      {#if summary.note}<span class="flag">&#9873; {summary.note}</span>{/if}
      <span>&#9678; {summary.visitorCount} visitors</span>
    {:else}
      <span><span class="dot" aria-hidden="true"></span>QUIET &middot; {summary.okCount} of {summary.total} phoning home</span>
      <span>&#9678; {summary.visitorCount} visitors &middot; {RANGE_LABELS[activeRange]}</span>
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
    <!-- The band, the tiles and the events -- later slices (#34, #35
         and the Svelte build's own step 3) render here. Deliberately
         empty for #36. -->
  </main>

  <footer class="foot" aria-label="Summary">
    {#if summary}
      <span>{summary.footSentence}</span>
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
