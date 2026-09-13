<script lang="ts">
  // Issue #37: the trace itself. Loads /api/trace (fixture-aware via
  // fetchTrace, same as every other read), measures its own container
  // width with a ResizeObserver so X0/X1 stay responsive, and renders one
  // SVG built by buildBandModel -- the geometry and label placement are
  // ported from docs/design/concepts/round-6/gen.py, not redesigned.
  import { fetchTrace } from '../api'
  import type { Range, TraceResponse } from '../types'
  import { buildBandModel, kindColor, type BandModel } from './model'

  let { range }: { range: Range } = $props()

  let container: HTMLDivElement | undefined = $state()
  let width: number = $state(1600)
  let trace: TraceResponse | null = $state(null)

  $effect(() => {
    // jsdom (App.svelte.test.ts renders this indirectly) has no
    // ResizeObserver; keep the 1600 default there rather than crash.
    if (!container || typeof ResizeObserver === 'undefined') return
    const observer = new ResizeObserver((entries) => {
      const w = entries[0]?.contentRect.width
      if (w) width = w
    })
    observer.observe(container)
    return () => observer.disconnect()
  })

  // Re-loads whenever range changes; a stale in-flight response (the
  // range changed again before it returned) is dropped rather than
  // clobbering newer data.
  $effect(() => {
    const r = range
    let cancelled = false
    fetchTrace(r)
      .then((data) => {
        if (!cancelled) trace = data
      })
      .catch(() => {
        if (!cancelled) trace = null
      })
    return () => {
      cancelled = true
    }
  })

  let model: BandModel | null = $derived(trace ? buildBandModel(trace, width) : null)
</script>

<div class="band" bind:this={container}>
  {#if model}
    <svg
      class="band-svg"
      viewBox={`0 0 ${width} ${model.bottom}`}
      width={width}
      height={model.bottom}
      role="img"
      aria-label="The trace: one heartbeat line per canary"
    >
      {#each model.bandLabels as bl (bl.text)}
        <text x={bl.x} y={bl.y} class="bandlab" fill={bl.color} text-anchor="end">{bl.text}</text>
      {/each}

      {#each model.lines as line (line.canaryId)}
        <line x1={model.x0} y1={line.y} x2={line.xTo} y2={line.y} stroke={line.color} stroke-width="1.2" opacity="0.6" />
      {/each}

      {#each model.silentDrops as drop (drop.canaryId)}
        <path d={drop.curveD} fill="none" stroke="var(--ink-3)" stroke-width="1.2" />
        <line x1={drop.xs + 20} y1={drop.yd} x2={model.x1} y2={drop.yd} stroke="var(--ink-3)" stroke-width="1" stroke-dasharray="2 5" opacity="0.8" />
        <circle cx={drop.xs} cy={drop.y} r="3.6" fill="var(--void)" stroke={drop.color} stroke-width="1.4" />
        <text x={drop.xs - 10} y={drop.yd + 3} class="bl" text-anchor="end">{drop.sentence}</text>
      {/each}

      {#each model.beatMarks as mark, i (i)}
        <rect x={mark.x - 0.7} y={mark.y - 2} width="1.4" height="4" fill="var(--ink-3)" opacity="0.55" />
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
  {/if}
</div>

<style>
  /* Page coordinates, like gen.py's .score: the band lines sit at
     BAND_TOP from the top of the scene whatever the labels above them
     climb to, so a quiet band does not float up into the sentence. */
  .band {
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    pointer-events: none;
  }
  .band-svg {
    display: block;
  }
  :global(.band-svg .ax) {
    font: 600 9.5px var(--mono);
    letter-spacing: 0.12em;
    fill: var(--ink-3);
    text-transform: uppercase;
  }
  :global(.band-svg .ax.now) {
    fill: var(--now);
    letter-spacing: 0.06em;
  }
  :global(.band-svg .axs) {
    font: 9px var(--sans);
    fill: var(--ink-3);
    text-anchor: middle;
    opacity: 0.8;
  }
  :global(.band-svg .axt) {
    stroke: var(--hair-2);
  }
  :global(.band-svg .brink) {
    stroke: var(--now);
    stroke-width: 1.6;
  }
  :global(.band-svg .bandlab) {
    font: 600 9.5px var(--mono);
  }
  :global(.band-svg .bl) {
    font: 10.5px var(--mono);
    fill: var(--ink);
  }
  :global(.band-svg .bl.dim) {
    fill: var(--ink-3);
    font-size: 9.5px;
  }
</style>
