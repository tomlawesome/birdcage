<script lang="ts">
  // Issue #56: what each canary's health did across the window, under the
  // tiles -- one row per canary, a bar from the response's since to its
  // until, and one line of English beside it. The tiles say what is true
  // now; this says what has been true, which is the question "it cleared
  // on its own" and "it has done this four times today" both live in.
  //
  // Takes the /api/history response as a prop from App.svelte's one
  // loader (issue #39's rule); no fetching here. Every placement,
  // lane and sentence comes from lib/history/model.ts -- this file only
  // positions what that returns, the same split Band and Tiles use.
  import type { HistoryResponse, Range } from './lib/types'
  import { historyRangeFor, historyRangeLabel, historyRows, historyTicks } from './lib/history/model'

  let { history, failed, range }: { history: HistoryResponse | null; failed: boolean; range: Range } = $props()

  // The window the section actually drew, which is the response's own --
  // the chip may have asked for a window the endpoint doesn't keep (see
  // historyRangeFor), so the heading names what came back, not what was
  // asked for.
  let windowRange = $derived(history?.range ?? historyRangeFor(range))
  let rows = $derived(history ? historyRows(history) : [])
  let ticks = $derived(history ? historyTicks(history.since, history.until, windowRange) : [])

  // Directly under the tallest tile (the tiles grid runs from y=430 to
  // about y=550 depending on how much a tile has to say). The whole
  // dashboard is absolutely positioned on a 1600x1000 canvas, so this
  // section has a fixed top like every other block.
  const TOP = 560
</script>

<div class="history" style:top="{TOP}px" aria-label="State history">
  <div class="grp">
    state history · {historyRangeLabel(windowRange)} ·
    {#if failed}<b>unavailable</b>{:else if rows.length === 0}<b>none</b>{:else}<b>{rows.length}</b> canaries{/if}
  </div>

  {#if failed}
    <div class="line">The cage's history is not answering &mdash; the rest of this page is still current.</div>
  {:else if rows.length === 0}
    <div class="line">
      Nothing recorded yet. An empty history is the cage working: no canary has left a healthy state in this window.
    </div>
  {:else}
    {#each rows as row (row.canaryId)}
      <div class="row">
        <div class="who">{row.name}</div>
        <div class="bar">
          {#each row.lanes as lane, li (li)}
            {#each lane as span (span.key)}
              <!-- Focusable, so a keyboard reaches the same start/end
                   detail a pointer gets from the title tooltip; there is
                   nothing to activate yet, so it carries no action. -->
              <button
                type="button"
                class="span {span.tier}"
                class:open={span.open}
                class:clipped={span.clippedStart}
                style:left="{span.leftPct}%"
                style:width="{span.widthPct}%"
                style:top="{(li * 100) / row.lanes.length}%"
                style:height="{100 / row.lanes.length}%"
                title={span.title}
                aria-label={span.title}
              ></button>
            {/each}
          {/each}
        </div>
        <div class="sum">{row.summary}</div>
      </div>
    {/each}
    <div class="row axis-row">
      <div></div>
      <div class="axis">
        {#each ticks as tick (tick.leftPct)}<span style:left="{tick.leftPct}%">{tick.label}</span>{/each}
      </div>
      <div></div>
    </div>
  {/if}
</div>

<style>
  .history {
    position: absolute;
    left: 54px;
    right: 80px;
  }
  /* The events heading's style exactly -- this is a second section of the
     same page, not a new kind of thing. */
  .grp {
    font: 600 9.5px var(--mono);
    letter-spacing: 0.16em;
    color: var(--ink-3);
    text-transform: uppercase;
  }
  .grp b {
    color: var(--ink-2);
    font-weight: 600;
  }
  .line {
    margin-top: 8px;
    font: italic 13px/1.5 var(--sans);
    color: var(--ink-3);
  }
  .row {
    display: grid;
    grid-template-columns: 132px 1fr 330px;
    column-gap: 14px;
    align-items: center;
    height: 26px;
  }
  .who {
    font: 700 11.5px var(--mono);
    color: var(--ink-2);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .bar {
    position: relative;
    height: 14px;
    background: var(--raised);
    border: 1px solid var(--hair);
    border-radius: 3px;
  }
  .span {
    position: absolute;
    /* A minute inside a week is a hairline; keep it wide enough to see
       and to hit, since it is also the focus target. */
    min-width: 3px;
    padding: 0;
    border: none;
    border-radius: 2px;
  }
  /* The tiers Tiles.svelte already speaks: the alarm colour for the
     critical states, the --repeat warning for a stalled rotation. */
  .span.crit {
    background: var(--alarm);
  }
  .span.warn {
    background: var(--repeat);
  }
  /* Birdcage not watching is not the canary's fault and not a clean bill
     of health: a dim neutral, the same ink the axis's dim marks use,
     hatched so it reads as a gap in the record rather than a state. */
  .span.unobs {
    background: repeating-linear-gradient(
      -45deg,
      var(--ink-3) 0 2px,
      transparent 2px 5px
    );
  }
  /* Still open: no right edge, so the span reads as running past now
     rather than ending at the bar's end. */
  .span.open {
    border-top-right-radius: 0;
    border-bottom-right-radius: 0;
  }
  /* Started before the window: no left edge either, same reasoning. */
  .span.clipped {
    border-top-left-radius: 0;
    border-bottom-left-radius: 0;
  }
  .span:focus-visible {
    outline: 1px solid var(--accent);
    outline-offset: 1px;
  }
  .sum {
    font: 11px var(--mono);
    color: var(--ink-2);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .axis-row {
    height: 14px;
  }
  .axis {
    position: relative;
    height: 100%;
  }
  .axis span {
    position: absolute;
    top: 0;
    transform: translateX(-50%);
    white-space: nowrap;
    font: 9px var(--mono);
    color: var(--ink-3);
  }
</style>
