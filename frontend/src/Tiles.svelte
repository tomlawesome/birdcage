<script lang="ts">
  // Issue #38: the canary tiles beneath the band (ADR-0004 rule 4). One
  // tile per canary, in lane order, box outline in the lane colour,
  // dashed --ink-3 with no fill when silent.
  //
  // Takes canaries (name, ports, status, the hits count) and trace (the
  // per-hit detail a status sentence like "swept 21:55" needs, plus the
  // server's "now" and last_hit -- Canary alone carries neither) as
  // props from App.svelte's one loader (issue #39); no fetching here.
  import type { Canary, Range, TraceResponse } from './lib/types'
  import { computeTileStatus, type TileHit } from './lib/sentence'

  let { canaries, trace, range }: { canaries: Canary[]; trace: TraceResponse; range: Range } = $props()

  const LANE_ORDER = ['lan', 'srv', 'iot', 'guest'] as const
  const RANGE_LABELS: Record<Range, string> = { '15m': '15 m', '1h': '1 h', '24h': '24 h', '14d': '14 d', '90d': '90 d' }

  let sortedCanaries: Canary[] = $derived(
    [...canaries].sort((a, b) => LANE_ORDER.indexOf(a.lane) - LANE_ORDER.indexOf(b.lane)),
  )
  let hitsById: Map<string, TileHit[]> = $derived(new Map(trace.canaries.map((tc) => [tc.id, tc.hits])))
</script>

<div class="tiles">
  {#each sortedCanaries as c (c.id)}
    {@const status = computeTileStatus(
      {
        status: c.status,
        last_heartbeat_at: c.last_heartbeat_at,
        silent_for_s: c.silent_for_s,
        ports: c.ports,
        hits: hitsById.get(c.id) ?? [],
        not_delivering: c.not_delivering,
        throttled_for_s: c.throttled_for_s,
        rotation_stalled: c.rotation_stalled,
        rotation_stalled_for_s: c.rotation_stalled_for_s,
        rotation_stalled_escalated: c.rotation_stalled_escalated,
        token_conflict_for_s: c.token_conflict_for_s,
      },
      trace.now,
      trace.last_hit,
    )}
    <div
      class="tile k-{c.lane}"
      class:silent={c.status === 'silent'}
      class:critical={c.status === 'token_conflict' || c.status === 'not_delivering' || c.status === 'throttled'}
      class:conflict={c.status === 'token_conflict'}
      class:degraded={c.status === 'rotation_stalled'}
    >
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
  /* issue #45's three visible tiers, loudest last (owner, 2026-09-17:
     the conflict tile must be "unmistakably the loudest thing on the
     page"). Critical states carry the alarm colour on the outline;
     degraded sits below them in the warning colour, muted toward the
     tile ground so its hairline cannot be mistaken for an alarm at a
     glance -- the bold --repeat status line still names it up close;
     conflict alone gets the backdrop and the glow below. */
  .tile.critical {
    border-color: var(--alarm);
  }
  /* issue #45, owner 2026-09-17: token conflict does not clear on its
     own -- "the whole tile should be outlined red with a red backdrop
     until the problem is fixed", louder than the other critical states
     above (border only), matching that it is the one state meaning
     "look at the box now". The backdrop is --alarm mixed at 18% into
     --raised, the strongest mix that keeps the bold .al status text at
     the 4.5:1 floor on it (4.73:1 measured; 22% drops it to 4.44). At
     18%, body text (--ink) is 12.66:1, --ink-2 5.89:1 and the iot lane
     name 4.78:1 -- all over AA. The 2px outline and the glow, not a
     stronger fill, are what carry it across the room. */
  .tile.conflict {
    border-width: 2px;
    border-color: var(--alarm);
    background: color-mix(in srgb, var(--alarm) 18%, var(--raised));
    box-shadow: 0 0 26px color-mix(in srgb, var(--alarm) 35%, transparent);
  }
  .tile.degraded {
    border-color: color-mix(in srgb, var(--repeat) 55%, var(--raised));
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
  /* issue #45's degraded tier (rotation stalled): reuses --repeat, the
     existing "attention but not critical" colour, rather than adding a
     new one. */
  .tile .st :global(.wn) {
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
