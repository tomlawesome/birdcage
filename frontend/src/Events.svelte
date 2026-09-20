<script lang="ts">
  // Issue #38: the events list beneath the tiles (ADR-0004 rule 5) --
  // one row per visitor from /api/visitors, newest first; a silent
  // canary (from /api/canaries) adds a DROPPED OUT row; a quiet day
  // (no visitors, nothing silent) shows one italic line instead. The
  // legend line lives here too -- static copy, ported from gen.py's
  // LEGEND constant, not derived from any response.
  //
  // Takes canaries, visitors and trace as props from App.svelte's one
  // loader (issue #39); no fetching here. "now" comes from trace.now,
  // never the browser clock or a visitor's own last_at.
  import type { Canary, Range, TraceResponse, Visitor } from './lib/types'
  import { buildEventRows, computeEventsHeading, QUIET_LINE, type EventRow } from './lib/sentence'

  let { canaries, visitors, trace, range }: { canaries: Canary[]; visitors: Visitor[]; trace: TraceResponse; range: Range } =
    $props()

  let heading = $derived(computeEventsHeading(canaries, visitors, range))
  let silentCanaries = $derived(canaries.filter((c) => c.status === 'silent'))
  let now = $derived(trace.now)
  // The merge-and-sort decision itself lives in lib/sentence/eventRow.ts's
  // buildEventRows (#74) -- testable without rendering this component.
  let rows: EventRow[] = $derived(buildEventRows(canaries, visitors, now))

  // Issue #56 inserted the state history section between the tiles and
  // here, so this moved down from 604 to clear it: the history section
  // starts at y=560 (History.svelte's TOP) and, for the small fleets
  // the fixtures use (up to a tile row's worth of canaries), ran to
  // about y=665 -- the same ~27px gap the tiles already leave above
  // this heading, carried past the new section instead of into it.
  //
  // Issue #56 follow-up: a row's summary can now wrap onto a second
  // line (History.svelte's .sum), so a fleet with a lot to say grows
  // taller than that. The 'history' dev fixture (?scene=history) is the
  // tallest case there is to measure against -- three rows, two of them
  // two lines -- and it runs to about y=695; this moved down again
  // (718 -> 749) to keep the same ~27px gap below that.
  const ROWS_TOP = 749
  const ROW_H = 70
  let silentOnly = $derived(visitors.length === 0 && silentCanaries.length > 0)
  let headingTop = $derived(silentOnly ? ROWS_TOP + 10 : ROWS_TOP - 26)
  let rowsTop = $derived(silentOnly ? ROWS_TOP + 36 : ROWS_TOP)
</script>

<div class="grp" style:top="{headingTop}px">
  {#each heading.segments as seg, i (i)}{#if seg.bold}<b>{seg.text}</b>{:else}{seg.text}{/if}{/each}
</div>

{#if heading.showQuietLine}
  <div class="quiet-line" style:top="{ROWS_TOP - 2}px">{QUIET_LINE}</div>
{:else}
  {#each rows as row, i (row.key)}
    <div class="row {row.cls}" style:top="{rowsTop + i * ROW_H}px">
      <div class="t">{row.time.primary}<small>{row.time.small}</small></div>
      <div class="kind">{row.kind.symbol} {row.kind.label}<small>{row.kind.small}</small></div>
      <div class="who">
        {#each row.who as seg, j (j)}{#if seg.bold}<b>{seg.text}</b>{:else if seg.cls}<span class={seg.cls}>{seg.text}</span>{:else}{seg.text}{/if}{/each}
      </div>
      <div class="acts">
        {#each row.actions as a, k (k)}<span class="pill" class:quiet={a.quiet}>{a.label}</span>{/each}
      </div>
    </div>
  {/each}
{/if}

<div class="legend" style:top="1057px">
  <span><span class="ln"></span>a line is a canary's heartbeat, unbroken</span>
  <span><span class="gap"></span>a drop is silence</span>
  <span
    >a rise is a visitor, its words at the top, by kind: <i style:background="var(--sweep)"></i>sweep <i
      style:background="var(--repeat)"
    ></i>repeat <i style:background="var(--inside)"></i>from inside <i style:background="var(--touch)"></i>one touch</span
  >
  <span>dim marks are single heartbeats where the axis is stretched</span>
  <span class="nw">&mdash; the brink &middot; now</span>
</div>

<style>
  .grp {
    position: absolute;
    left: 54px;
    font: 600 9.5px var(--mono);
    letter-spacing: 0.16em;
    color: var(--ink-3);
    text-transform: uppercase;
  }
  .grp :global(b) {
    color: var(--ink-2);
    font-weight: 600;
  }
  .quiet-line {
    position: absolute;
    left: 54px;
    font: italic 13px/1.5 var(--sans);
    color: var(--ink-3);
  }
  .row {
    position: absolute;
    left: 40px;
    right: 80px;
    height: 70px;
    display: grid;
    grid-template-columns: 92px 132px 1fr auto;
    column-gap: 16px;
    align-items: center;
    padding-left: 14px;
    border-bottom: 1px solid var(--hair);
  }
  .row::before {
    content: '';
    position: absolute;
    left: 0;
    top: 10px;
    bottom: 10px;
    width: 3px;
    border-radius: 2px;
    background: var(--k);
  }
  .row.k-sw {
    --k: var(--sweep);
  }
  .row.k-rp {
    --k: var(--repeat);
  }
  .row.k-in {
    --k: var(--inside);
  }
  .row.k-tc {
    --k: var(--touch);
  }
  .row.k-off {
    --k: var(--ink-2);
  }
  .row .t {
    font: 11px var(--mono);
    color: var(--ink);
  }
  .row .t small {
    display: block;
    font: 10px var(--mono);
    color: var(--ink-3);
  }
  .row .kind {
    font: 700 11px var(--mono);
    letter-spacing: 0.06em;
    color: var(--k);
    white-space: nowrap;
  }
  .row .kind small {
    display: block;
    font: 10px var(--mono);
    color: var(--ink-3);
    letter-spacing: 0;
    margin-top: 3px;
    font-weight: 500;
  }
  .row .who {
    font: 12.5px var(--sans);
    color: var(--ink-2);
    line-height: 1.45;
  }
  .row .who :global(.ip) {
    font: 12.5px var(--mono);
    color: var(--ink);
  }
  .row .who :global(b) {
    color: var(--ink);
    font-weight: 600;
  }
  .row .acts {
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
  .legend {
    position: absolute;
    left: 54px;
    right: 80px;
    font: 11px var(--sans);
    color: var(--ink-3);
    display: flex;
    gap: 22px;
    flex-wrap: wrap;
  }
  .legend i {
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    vertical-align: -1px;
    margin-right: 5px;
  }
  .legend .ln {
    display: inline-block;
    width: 22px;
    height: 0;
    border-top: 1.5px solid var(--lan);
    vertical-align: 3px;
    margin-right: 6px;
    opacity: 0.7;
  }
  .legend .gap {
    display: inline-block;
    width: 22px;
    height: 0;
    border-top: 1.5px dashed var(--ink-3);
    vertical-align: 3px;
    margin-right: 6px;
  }
  .legend .nw {
    color: var(--now);
  }
</style>
