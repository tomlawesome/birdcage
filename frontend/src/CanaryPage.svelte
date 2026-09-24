<script lang="ts">
  // Issue #118: one canary's own page (round 7, direction O -- the line,
  // alone · ledger). Reached from its tile on the cage; keeps the shell
  // App.svelte draws and fills the main area with four blocks: the line
  // at its own scale, the self-test as a strip of cards, the history as
  // a thread, and the facts with the actions the state earns.
  //
  // Takes its data as props, like every other block on the dashboard --
  // App.svelte owns the fetching (issue #39's rule), including this
  // page's own /api/canary read.
  import type { CanaryPageResponse, HistoryResponse, Range, RunsResponse, TraceResponse, Visitor } from './lib/types'
  import CanaryLine from './lib/band/CanaryLine.svelte'
  import { selfTestCards, silences, traceOf, type CanaryPageInput } from './lib/canary/model'
  import { canaryActions, canaryCrumb, canarySentence, selfTestHeading } from './lib/canary/sentence'
  import { answerWords, cardClass, gradeWords, SELF_TEST_NOTE } from './lib/canary/ledger'
  import { threadFooter, threadRows } from './lib/canary/thread'
  import { factRows } from './lib/canary/facts'
  import { runRows, stageTimeline } from './lib/canary/runs'
  import { formatClock } from './lib/sentence/time'

  let {
    page,
    trace,
    visitors,
    history,
    range,
    runs = null,
  }: {
    page: CanaryPageResponse
    trace: TraceResponse
    visitors: Visitor[]
    history: HistoryResponse | null
    range: Range
    runs?: RunsResponse | null
  } = $props()

  let input: CanaryPageInput = $derived({ page, trace, visitors, history })

  let crumb = $derived(canaryCrumb(input))
  let sentence = $derived(canarySentence(input))
  let heading = $derived(selfTestHeading(input))
  let cards = $derived(selfTestCards(page.canary))
  let rows = $derived(threadRows(input))
  let facts = $derived(factRows(input))
  let actions = $derived(canaryActions(input))

  // ADR-0012 (issue #116): a scanner's own ordered-scan proof -- the
  // open run's stage timeline and the Runs list, shown only on a
  // scanner's own page (decision 11), beside the state history and
  // self-test ledger every canary page already has.
  let isScanner = $derived(page.facts.kind === 'scanner')
  let stageSteps = $derived(stageTimeline(page.canary.run?.stage))
  let runList = $derived(runRows(runs, trace.now))
  let dbRefresh = $derived(page.canary.db_refresh)

  let lineInput = $derived({
    canary: page.canary,
    trace: traceOf(input),
    now: trace.now,
    range,
    runs: page.self_test_runs,
    silences: silences(input),
  })

  // The lower half's own coordinates, as gen.py sets them: the ledger
  // and the facts start together, the thread sits under the ledger.
  const LOWER = 420
  const THREAD_TOP = LOWER + 190

  // Every mention of this canary -- its name in the crumb and the hero,
  // its lane in the facts -- carries its own lane colour, the same one
  // its tile and its line already use.
  const LANE_VAR: Record<string, string> = {
    lan: 'var(--lan)',
    srv: 'var(--srv)',
    iot: 'var(--iot)',
    guest: 'var(--guest)',
  }
  let laneColor = $derived(LANE_VAR[page.canary.lane] ?? 'var(--ink-2)')
</script>

<div class="page" style:--c={laneColor}>
<div class="grp" style:top="70px">
  {#each crumb as seg, i (i)}{#if seg.bold}<b class={seg.cls}>{seg.text}</b>{:else}<span class={seg.cls}>{seg.text}</span
    >{/if}{/each}
</div>
<div class="hero" style:top="94px">
  {#each sentence.hero as seg, i (i)}{#if seg.bold}<b class={seg.cls}>{seg.text}</b>{:else}<span class={seg.cls}
      >{seg.text}</span
    >{/if}{/each}
</div>
<div class="sub" style:top="134px">
  {#each sentence.sub as seg, i (i)}{#if seg.bold}<b class={seg.cls}>{seg.text}</b>{:else}<span class={seg.cls}
      >{seg.text}</span
    >{/if}{/each}
</div>

<CanaryLine input={lineInput} />

<!-- The self-test as a ledger (ADR-0004 rule 3). -->
<div class="col ledger" style:top="{LOWER}px">
  <h3>
    {heading.lead}{#if heading.verdict}<span class={heading.verdict.cls}>{heading.verdict.text}</span
      >{/if}{heading.tail}{#if heading.note}{' · '}<b>{heading.note}</b>{/if}
  </h3>
  {#if cards.length === 0}
    <div class="none">No self-test has completed for this canary yet — nothing to grade, which is not a fault.</div>
  {:else}
    <div class="strip">
      {#each cards as card (card.service)}
        <div class="svc {cardClass(card)}">
          <div class="n">{card.service}{#if card.port}<small>:{card.port}</small>{/if}</div>
          <div class="r">{answerWords(card)}</div>
          <div class="g">{gradeWords(card)}</div>
        </div>
      {/each}
    </div>
    <div class="strip-note">
      {#each SELF_TEST_NOTE as seg, i (i)}{#if seg.bold}<b>{seg.text}</b>{:else}{seg.text}{/if}{/each}
    </div>
  {/if}
</div>

<!-- The history as a thread (ADR-0004 rule 4). -->
<div class="col thread-col" style:top="{THREAD_TOP}px">
  <h3>history &middot; every state this canary has been in &middot; newest first</h3>
  <div class="thread">
    {#each rows as row (row.key)}
      <div class="ev {row.dot}">
        <span class="t">{row.when}</span><b>{row.state}</b> —
        {#each row.detail as seg, i (i)}{#if seg.bold}<b class={seg.cls}>{seg.text}</b>{:else}<span class={seg.cls}
            >{seg.text}</span
          >{/if}{/each}
      </div>
    {/each}
    <div class="more">{threadFooter(input)}</div>
  </div>
</div>

<!-- The facts, and the actions the state earns (ADR-0004 rule 5). -->
<div class="col facts-col" style:top="{LOWER}px">
  <h3>this canary</h3>
  <div class="facts">
    {#each facts as row (row.label)}
      <span>{row.label}</span><span class={row.accent ? 'c' : ''}>{row.value}</span>
    {/each}
  </div>
  <div class="acts">
    {#each actions as action (action.label)}
      <span class="pill" class:quiet={action.quiet}>{action.label}</span>
    {/each}
  </div>
</div>

<!-- ADR-0012 decision 11 (issue #116): a scanner's own proof -- the
     open run's stage timeline and the Runs list, beside the history
     thread and the self-test ledger every canary page already has. -->
{#if isScanner}
  <div class="col scan-col" style:top="{THREAD_TOP + 260}px">
    <h3>scan stage</h3>
    {#if stageSteps.length > 0}
      <div class="stages" role="list" aria-label="Scan stage">
        {#each stageSteps as step (step.stage)}
          <div class="stage {step.state}" role="listitem">{step.label}</div>
        {/each}
      </div>
    {:else}
      <div class="none">No scan is open right now.</div>
    {/if}
    {#if dbRefresh}
      <div class="db-refresh">vulnerability list refresh failing since {formatClock(dbRefresh.failing_since)}</div>
    {/if}

    <h3 class="runs-h">runs</h3>
    {#if runList.length === 0}
      <div class="none">No scan has been ordered for this canary yet.</div>
    {:else}
      <div class="runs" role="table" aria-label="Runs">
        {#each runList as row (row.key)}
          <div class="run-row" role="row">
            <span class="trig">{row.trigger}</span>
            <span class="issued">{row.issued}</span>
            <span class="ended">{row.ended}</span>
            <span class="verdict {row.verdictCls}">{row.verdict}</span>
            <span class="last-stage">{row.lastStage}</span>
            <span class="reason">{row.reason}</span>
          </div>
        {/each}
      </div>
    {/if}
  </div>
{/if}

<div class="legend" style:top="912px">
  <span><span class="ln"></span>the line is this canary's heartbeat, unbroken</span>
  <span><span class="gap"></span>a drop is silence</span>
  <span
      ><span class="tick"></span>a hollow tick under the line is birdcage testing its own canary{#if page.facts
        .self_test_enabled}, {page.facts.self_test_schedule} daily{/if}</span
    >
  <span
    >a rise is a visitor:
    <i style="background:var(--sweep)"></i>sweep
    <i style="background:var(--repeat)"></i>repeat
    <i style="background:var(--inside)"></i>from inside
    <i style="background:var(--touch)"></i>one touch</span
  >
  <span class="nw">— the brink &middot; now</span>
</div>
</div>

<style>
  /* A plain static wrapper: it carries the canary's lane colour as --c
     for everything below without becoming a containing block, so every
     block here still positions against the shell's own .scene. */
  .page {
    display: contents;
  }

  /* The sentence block, at the shell's own coordinates -- the same
     left rail and the same three sizes App.svelte uses for the cage, so
     moving between the two pages does not move the type. */
  .grp {
    position: absolute;
    left: 54px;
    font: 600 9.5px var(--mono);
    letter-spacing: 0.16em;
    color: var(--ink-3);
    text-transform: uppercase;
  }
  .grp b {
    color: var(--ink-2);
    font-weight: 600;
  }
  .grp :global(.r) {
    color: var(--alarm);
  }
  .grp :global(.c),
  .hero :global(.c) {
    color: var(--c);
  }
  .hero {
    position: absolute;
    left: 54px;
    font: 500 26px/1.2 var(--sans);
    color: var(--ink);
    letter-spacing: -0.01em;
  }
  .hero :global(b) {
    font-weight: 700;
  }
  .hero :global(.ok) {
    color: var(--ok);
  }
  .hero :global(.r) {
    color: var(--alarm);
  }
  .sub {
    position: absolute;
    left: 54px;
    width: 900px;
    font: 13px/1.55 var(--sans);
    color: var(--ink-2);
  }
  .sub :global(b) {
    color: var(--ink);
    font-weight: 600;
  }
  .sub :global(.ip) {
    font: 12.5px var(--mono);
    color: var(--ink);
  }

  .col {
    position: absolute;
  }
  .ledger {
    left: 54px;
    width: 1000px;
  }
  .thread-col {
    left: 54px;
    width: 860px;
  }
  .facts-col {
    left: 1100px;
    width: 400px;
  }
  /* ADR-0012 (issue #116): a scanner's own stage timeline and Runs
     list, beside the thread and the facts columns above. */
  .scan-col {
    left: 54px;
    width: 1440px;
  }
  .runs-h {
    margin-top: 16px;
  }
  .stages {
    display: flex;
    gap: 6px;
  }
  .stage {
    padding: 4px 10px;
    border-radius: 999px;
    font: 600 11px var(--mono);
    color: var(--ink-3);
    border: 1px solid var(--hair-2);
  }
  .stage.done {
    color: var(--ink);
    border-color: var(--ok);
  }
  .stage.current {
    color: var(--ink);
    border-color: var(--repeat);
    background: var(--raised);
  }
  .db-refresh {
    margin-top: 8px;
    font: 12px var(--sans);
    color: var(--alarm);
  }
  .runs {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .run-row {
    display: grid;
    grid-template-columns: 70px 140px 140px 70px 170px 1fr;
    column-gap: 12px;
    font: 11.5px var(--mono);
    color: var(--ink-2);
  }
  .run-row .verdict.ok {
    color: var(--ok);
  }
  .run-row .verdict.al {
    color: var(--alarm);
  }
  .run-row .verdict.wn {
    color: var(--repeat);
  }
  .col h3 {
    margin: 0 0 10px;
    font: 600 9.5px var(--mono);
    letter-spacing: 0.16em;
    color: var(--ink-3);
    text-transform: uppercase;
  }
  .col h3 b {
    color: var(--ink-2);
    font-weight: 600;
  }
  .col h3 :global(.ok) {
    color: var(--ok);
  }
  .col h3 :global(.r) {
    color: var(--ink);
  }
  .none {
    font: italic 12px/1.5 var(--sans);
    color: var(--ink-3);
  }

  /* One card per service, outlined in the grade's colour: --ok answered,
     --ink did not answer, dashed --ink-3 untested. Untested is not a
     fault, so it never borrows the alarm colour. */
  .strip {
    display: flex;
    gap: 12px;
  }
  .svc {
    --b: var(--ok);
    width: 176px;
    padding: 10px 12px 9px;
    border: 1px solid var(--b);
    border-radius: 8px;
    background: var(--raised);
  }
  .svc .n {
    font: 700 12px var(--mono);
    color: var(--ink);
  }
  .svc .n small {
    color: var(--ink-3);
    font-weight: 500;
    margin-left: 6px;
  }
  .svc .r {
    margin-top: 4px;
    font: 11px var(--mono);
    color: var(--b);
  }
  .svc .g {
    margin-top: 6px;
    font: 600 9px var(--mono);
    letter-spacing: 0.14em;
    text-transform: uppercase;
    color: var(--ink-3);
  }
  .svc.no {
    --b: var(--ink);
    background: transparent;
  }
  .svc.no .r {
    font-weight: 700;
  }
  .svc.un {
    --b: var(--ink-3);
    border-style: dashed;
    background: transparent;
  }
  .svc.un .r {
    color: var(--ink-3);
  }
  .strip-note {
    margin-top: 10px;
    font: italic 12px/1.5 var(--sans);
    color: var(--ink-3);
  }
  .strip-note :global(b) {
    color: var(--ink-2);
    font-style: normal;
  }

  /* The thread: the band's own dots down the left, one line per state. */
  .thread {
    position: relative;
    padding-left: 26px;
  }
  .thread::before {
    content: '';
    position: absolute;
    left: 6px;
    top: 6px;
    bottom: 6px;
    width: 0;
    border-left: 1px solid var(--hair-2);
  }
  .ev {
    position: relative;
    margin: 0 0 9px;
    font: 12.5px/1.45 var(--sans);
    color: var(--ink-2);
  }
  .ev::before {
    content: '';
    position: absolute;
    left: -24px;
    top: 6px;
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--void);
    border: 1.4px solid var(--ink-3);
  }
  .ev.ok::before {
    border-color: var(--ok);
    background: var(--ok);
  }
  .ev.fault::before {
    border-color: var(--ink);
    background: var(--ink);
  }
  .ev.live::before {
    border-color: var(--ink);
    background: var(--void);
    border-width: 2px;
  }
  .ev .t {
    font: 11px var(--mono);
    color: var(--ink-3);
    display: inline-block;
    width: 120px;
  }
  .ev b {
    color: var(--ink);
    font-weight: 600;
  }
  .ev :global(.live) {
    color: var(--ink);
    font-weight: 700;
  }
  .ev :global(.ip) {
    font: 11.5px var(--mono);
    color: var(--ink);
  }
  .more {
    color: var(--ink-3);
    font-style: italic;
    font-size: 12px;
  }

  .facts {
    display: grid;
    grid-template-columns: 110px 1fr;
    row-gap: 6px;
    column-gap: 12px;
    font: 11.5px var(--mono);
    color: var(--ink);
  }
  .facts span:nth-child(odd) {
    color: var(--ink-3);
  }
  .facts :global(.c) {
    color: var(--c);
  }
  .acts {
    margin-top: 16px;
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
    border-top: 1.5px solid var(--c);
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
  .legend .tick {
    display: inline-block;
    width: 6px;
    height: 6px;
    border-radius: 50%;
    border: 1px solid var(--ink-3);
    vertical-align: -1px;
    margin-right: 6px;
  }
  .legend .nw {
    color: var(--now);
  }
</style>
