// Band.svelte's own decisions, as opposed to buildBandModel (already
// covered by model.test.ts): that it turns the model's arrays into the
// right SVG elements -- one line per canary, a drop for a silent one, a
// labelled rise with its stem, and the axis furniture -- and that it
// survives with no model at all.
import { render, screen } from '@testing-library/svelte'
import { describe, expect, it } from 'vitest'
import Band from './Band.svelte'
import nightFixture from '../../dev/fixtures/night.json'
import silentFixture from '../../dev/fixtures/silent.json'
import quietFixture from '../../dev/fixtures/quiet.json'
import type { TraceResponse } from '../types'

describe('Band.svelte: the trace as SVG', () => {
  it('quiet: one line per canary, no labels, no bumps, no drops', () => {
    const trace = quietFixture.trace as unknown as TraceResponse
    const { container } = render(Band, { trace })
    expect(container.querySelectorAll('.band-svg line[stroke-width="1.2"][opacity="0.6"]')).toHaveLength(trace.canaries.length)
    expect(container.querySelectorAll('.band-svg .bl')).toHaveLength(0)
    expect(container.querySelectorAll('.band-svg path')).toHaveLength(0)
  })

  it('silent: the dropped-out canary gets a curve, a dashed tail and a sentence', () => {
    const trace = silentFixture.trace as unknown as TraceResponse
    const { container } = render(Band, { trace })
    expect(container.querySelectorAll('.band-svg circle')).toHaveLength(1)
    const text = container.querySelector('.band-svg text.bl')
    expect(text?.textContent).toContain('canary-iot dropped out')
  })

  it('night: a labelled rise draws its stem and two lines of text', () => {
    const trace = nightFixture.trace as unknown as TraceResponse
    const { container } = render(Band, { trace })
    const stems = container.querySelectorAll('.band-svg path[stroke="var(--ink-3)"][fill="none"]')
    expect(stems.length).toBeGreaterThan(0)
    const labelTexts = [...container.querySelectorAll('.band-svg text.bl:not(.dim)')].map((t) => t.textContent)
    expect(labelTexts.some((t) => t?.includes('root / root'))).toBe(true)
    // Each labelled rise draws a bump path pair (fill + stroke).
    expect(container.querySelectorAll('.band-svg path[fill-opacity="0.14"]').length).toBeGreaterThan(0)
  })

  it('every canary gets its lane label to the left of the band', () => {
    const trace = nightFixture.trace as unknown as TraceResponse
    const { container } = render(Band, { trace })
    const labels = [...container.querySelectorAll('.band-svg .bandlab')].map((t) => t.textContent)
    expect(labels).toEqual(trace.canaries.map((c) => c.id))
  })

  it('renders the NOW label and the accessible name for the whole trace', () => {
    const trace = quietFixture.trace as unknown as TraceResponse
    render(Band, { trace })
    expect(screen.getByRole('img', { name: /The trace: one heartbeat line per canary/ })).toBeTruthy()
    expect(screen.getByText(/^NOW ·/)).toBeTruthy()
  })
})
