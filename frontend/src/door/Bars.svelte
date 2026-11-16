<script lang="ts">
  // The canvas behind the door: ./bars.ts draws it. Started once when the
  // canvas mounts and stopped when it goes; neither prop restarts it, so
  // the simulation is never re-seeded mid-visit.
  import { untrack } from 'svelte'
  import { startBars } from './bars'

  let { frozenAt, opening = () => false }: { frozenAt?: number; opening?: () => boolean } = $props()

  let canvas: HTMLCanvasElement | undefined = $state()

  $effect(() => {
    const c = canvas
    if (!c) return
    return untrack(() => startBars(c, { frozenAt, opening: () => opening() }))
  })
</script>

<canvas class="bars" bind:this={canvas} aria-hidden="true"></canvas>
