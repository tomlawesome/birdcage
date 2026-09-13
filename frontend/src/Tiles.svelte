<script lang="ts">
  // Issue #38: the canary tiles beneath the band (ADR-0004 rule 4). One
  // tile per canary, in lane order, box outline in the lane colour,
  // dashed --ink-3 with no fill when silent.
  //
  // Reads both fetchCanaries (name, ports, status, the hits count) and
  // fetchTrace (the per-hit detail a status sentence like "swept 21:55"
  // needs, plus the server's "now" -- Canary alone carries neither).
  import { fetchCanaries, fetchTrace } from './lib/api'
  import type { Canary, Range } from './lib/types'
  import { computeTileStatus, type TileHit } from './lib/sentence'

  let { range }: { range: Range } = $props()

  const LANE_ORDER = ['lan', 'srv', 'iot', 'guest'] as const
  const RANGE_LABELS: Record<Range, string> = { '15m': '15 m', '1h': '1 h', '24h': '24 h', '14d': '14 d', '90d': '90 d' }

  let canaries: Canary[] = $state([])
  let hitsById: Map<string, TileHit[]> = $state(new Map())
  let now: string = $state(new Date().toISOString())

  $effect(() => {
    const r = range
    ;(async () => {
      try {
        const [c, t] = await Promise.all([fetchCanaries(r), fetchTrace(r)])
        canaries = [...c.canaries].sort((a, b) => LANE_ORDER.indexOf(a.lane) - LANE_ORDER.indexOf(b.lane))
        hitsById = new Map(t.canaries.map((tc) => [tc.id, tc.hits]))
        now = t.now
      } catch {
        canaries = []
        hitsById = new Map()
      }
    })()
  })
</script>

<div class="tiles">
  {#each canaries as c (c.id)}
    {@const status = computeTileStatus(
      { status: c.status, last_heartbeat_at: c.last_heartbeat_at, silent_for_s: c.silent_for_s, ports: c.ports, hits: hitsById.get(c.id) ?? [] },
      now,
    )}
    <div class="tile k-{c.lane}" class:silent={c.status === 'silent'}>
      <div class="n">{c.name}<small>on {c.lane}</small></div>
      <div class="st">
        {#each status.lines as line, i (i)}
          {#if i > 0}<br />{/if}
          {#each line as seg, j (j)}{#if seg.cls}<span class={seg.cls}>{seg.text}</span>{:else}{seg.text}{/if}{/each}
        {/each}
      </div>
      <div class="pt">{c.ports}</div>
      <div class="big">{c.hits}<small>hits &middot; {RANGE_LABELS[range]}</small></div>
      {#if c.status === 'silent'}
        <div class="acts">
          <span class="pill">open {c.name} &#9656;</span>
          <span class="pill quiet">mark as maintenance</span>
        </div>
      {/if}
    </div>
  {/each}
</div>

<style>
  .tiles {
    position: absolute;
    top: 430px;
    left: 54px;
    right: 80px;
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 18px;
  }
  .tile {
    --c: var(--ink-2);
    position: relative;
    padding: 14px 16px 12px;
    background: var(--raised);
    border: 1px solid var(--c);
    border-radius: 8px;
  }
  .tile.silent {
    border-color: var(--ink-3);
    border-style: dashed;
    background: transparent;
  }
  .tile.k-lan {
    --c: var(--lan);
  }
  .tile.k-srv {
    --c: var(--srv);
  }
  .tile.k-iot {
    --c: var(--iot);
  }
  .tile.k-guest {
    --c: var(--guest);
  }
  .tile .n {
    font: 700 12.5px var(--mono);
    color: var(--c);
  }
  .tile .n small {
    font-weight: 500;
    color: var(--ink-3);
    margin-left: 8px;
  }
  .tile .st {
    margin-top: 6px;
    padding-right: 96px;
    font: 11px var(--mono);
    color: var(--ink-2);
  }
  .tile .st :global(.ok) {
    color: var(--ok);
  }
  .tile .st :global(.al) {
    color: var(--alarm);
    font-weight: 700;
  }
  .tile .st :global(.rp) {
    color: var(--repeat);
    font-weight: 700;
  }
  .tile .st :global(.off) {
    color: var(--ink);
    font-weight: 700;
  }
  .tile .pt {
    margin-top: 8px;
    font: 10px var(--mono);
    color: var(--ink-3);
  }
  .tile .big {
    position: absolute;
    right: 16px;
    top: 12px;
    font: 600 20px var(--sans);
    color: var(--ink);
    letter-spacing: -0.02em;
  }
  .tile .big small {
    display: block;
    font: 9px var(--mono);
    color: var(--ink-3);
    letter-spacing: 0.12em;
    text-transform: uppercase;
    text-align: right;
    font-weight: 600;
  }
  .tile .acts {
    margin-top: 10px;
    display: flex;
    gap: 8px;
    align-items: center;
    flex-wrap: wrap;
  }
  .pill {
    font: 600 11px var(--sans);
    color: var(--accent);
    border: 1px solid var(--hair-2);
    border-radius: 999px;
    padding: 3px 12px;
    white-space: nowrap;
  }
  .pill.quiet {
    color: var(--ink-3);
  }
</style>
