<script lang="ts">
  // Issue #118: this canary's line, alone, at its own scale. The same
  // component shape as Band.svelte -- measure the container, build one
  // model, draw it -- and the same split: every number comes from
  // lib/band/single.ts, which reuses the band's own axis, segments,
  // bump and placement code rather than a second copy of it.
  import { buildCanaryLineModel, type CanaryLineInput, type CanaryLineModel } from './single'
  import { kindColor } from './model'

  let { input }: { input: CanaryLineInput } = $props()

  let container: HTMLDivElement | undefined = $state()
  let width: number = $state(1600)

  $effect(() => {
    // jsdom has no ResizeObserver; keep the 1600 default there rather
    // than crash, exactly as Band.svelte does.
    if (!container || typeof ResizeObserver === 'undefined') return
    const observer = new ResizeObserver((entries) => {
      const w = entries[0]?.contentRect.width
      if (w) width = w
    })
    observer.observe(container)
    return () => observer.disconnect()
  })

  let model: CanaryLineModel = $derived(buildCanaryLineModel(input, width))
</script>

<div class="line" bind:this={container}>
  <svg
    class="line-svg"
    viewBox={`0 0 ${width} ${model.bottom}`}
    {width}
    height={model.bottom}
    role="img"
    aria-label={`${model.name}: its heartbeat, its silences and its self-test runs`}
  >
    <text x={model.x0 - 10} y={model.y + 3} class="bandlab" fill={model.color} text-anchor="end">{model.name}</text>

    <line x1={model.x0} y1={model.y} x2={model.xTo} y2={model.y} stroke={model.color} stroke-width="1.6" opacity="0.7" />

    {#if model.drop}
      <path d={model.drop.curveD} fill="none" stroke="var(--ink-3)" stroke-width="1.2" />
      <line
        x1={model.drop.xs + 20}
        y1={model.drop.yd}
        x2={model.x1}
        y2={model.drop.yd}
        stroke="var(--ink-3)"
        stroke-width="1"
        stroke-dasharray="2 5"
        opacity="0.8"
      />
      <circle cx={model.drop.xs} cy={model.y} r="3.8" fill="var(--void)" stroke={model.color} stroke-width="1.5" />
      <text x={model.drop.xs - 10} y={model.drop.yd + 3} class="bl" text-anchor="end">{model.drop.sentence}</text>
    {/if}

    {#each model.beatMarks as x, i (i)}
      <rect x={x - 0.7} y={model.y - 2} width="1.4" height="4" fill="var(--ink-3)" opacity="0.55" />
    {/each}

    <!-- The fortnight's earlier silences: the band's own hollow ink
         circle, labelled to the left so a failed self-test's stem to the
         right of a mark never crosses the words. -->
    {#each model.silenceMarks as mark, i (i)}
      <circle cx={mark.x} cy={model.y} r="3.2" fill="var(--void)" stroke="var(--ink-3)" stroke-width="1.2" />
      <text x={mark.labelX} y={mark.labelY} class="bl dim" text-anchor="end">{mark.text}</text>
    {/each}

    {#each model.bumps as bump, i (i)}
      <path d={bump.d} fill={kindColor(bump.kind)} fill-opacity="0.14" stroke="none" />
      <path d={bump.d} fill="none" stroke={kindColor(bump.kind)} stroke-width="1.5" stroke-linejoin="round" />
    {/each}

    {#each model.labels as label, i (i)}
      <text x={label.x} y={label.y - 16} class="bl" text-anchor={label.anchor}
        ><tspan fill={kindColor(label.kind)}>✱ </tspan>{label.l1}</text
      >
      <text x={label.x} y={label.y - 4} class="bl dim" text-anchor={label.anchor}>{label.l2}</text>
    {/each}

    <!-- Under the line, never above it: birdcage prodding its own canary
         is not a visitor, and a mark above the line is what a visitor
         looks like. -->
    {#each model.selfTestTicks as tick, i (i)}
      {#if tick.failed}
        <circle cx={tick.x} cy={model.y + 10} r="3.4" fill="var(--ink)" stroke="var(--ink)" stroke-width="1.2" />
      {:else}
        <circle cx={tick.x} cy={model.y + 10} r="2.8" fill="var(--void)" stroke="var(--ink-3)" stroke-width="1.1" />
      {/if}
    {/each}

    {#if model.failedRun}
      <line
        x1={model.failedRun.x}
        y1={model.y + 6}
        x2={model.failedRun.x}
        y2={model.failedRun.stemTop}
        stroke="var(--ink-3)"
        stroke-width="1"
      />
      <text x={model.failedRun.x} y={model.failedRun.y1} class="bl" text-anchor="middle"
        >{model.failedRun.lead}<tspan fill="var(--ink)" font-weight="700">{model.failedRun.failed}</tspan></text
      >
      <text x={model.failedRun.x} y={model.failedRun.y2} class="bl dim" text-anchor="middle">{model.failedRun.detail}</text>
    {/if}

    {#each model.axisTicks as tick (tick.label)}
      <text x={tick.x} y={model.axisY} class="ax">{tick.label}</text>
      <line x1={tick.x} y1={model.axisY - 16} x2={tick.x} y2={model.axisY - 10} class="axt" />
    {/each}
    <text x={model.now.x} y={model.axisY} class="ax now" text-anchor="end">{model.now.text}</text>

    {#each model.dayTicks as tick, i (i)}
      <line x1={tick.x} y1={model.axisY - 14} x2={tick.x} y2={model.axisY - 10} class="axt" opacity="0.6" />
      {#if tick.label}
        <text x={tick.x} y={model.axisY + 16} class="axs">{tick.label}</text>
      {/if}
    {/each}

    {#each model.captions as caption (caption.text)}
      <text x={caption.x} y={model.axisY + 16} class="axs">{caption.text}</text>
    {/each}

    <line x1={model.brink.x} y1={model.brink.yTop} x2={model.brink.x} y2={model.brink.yBottom} class="brink" />
  </svg>
</div>

<style>
  /* Page coordinates, like Band.svelte's: the line sits at LINE_Y from
     the top of the scene whatever the labels above it climb to. */
  .line {
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    pointer-events: none;
  }
  .line-svg {
    display: block;
  }
  :global(.line-svg .ax) {
    font: 600 9.5px var(--mono);
    letter-spacing: 0.12em;
    fill: var(--ink-3);
    text-transform: uppercase;
  }
  :global(.line-svg .ax.now) {
    fill: var(--now);
    letter-spacing: 0.06em;
  }
  :global(.line-svg .axs) {
    font: 9px var(--sans);
    fill: var(--ink-3);
    text-anchor: middle;
    opacity: 0.8;
  }
  :global(.line-svg .axt) {
    stroke: var(--hair-2);
  }
  :global(.line-svg .brink) {
    stroke: var(--now);
    stroke-width: 1.6;
  }
  :global(.line-svg .bandlab) {
    font: 600 10.5px var(--mono);
  }
  :global(.line-svg .bl) {
    font: 10.5px var(--mono);
    fill: var(--ink);
  }
  :global(.line-svg .bl.dim) {
    fill: var(--ink-3);
    font-size: 9.5px;
  }
</style>
