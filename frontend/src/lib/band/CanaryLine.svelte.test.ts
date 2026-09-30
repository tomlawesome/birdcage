// CanaryLine.svelte's own decisions, as opposed to buildCanaryLineModel
// (already covered by single.test.ts): that it turns the model's fields
// into the right SVG elements -- the line, a drop when silent, silence
// marks, self-test ticks, a failed-run callout and a labelled rise.
import { render, screen } from '@testing-library/svelte'
import { describe, expect, it } from 'vitest'
import CanaryLine from './CanaryLine.svelte'
import { sceneInput, type SceneName } from '../canary/fixtures'
import { silences, traceOf } from '../canary/model'
import { buildCanaryLineModel, type CanaryLineInput } from './single'

function lineInput(scene: SceneName): CanaryLineInput {
  const input = sceneInput(scene)
  return {
    canary: input.page.canary,
    trace: traceOf(input),
    now: input.trace.now,
    range: '14d',
    runs: input.page.self_test_runs,
    silences: silences(input),
  }
}

describe('CanaryLine.svelte: one canary as SVG', () => {
  it('quiet: the full-width line, its name label, no drop, one tick per self-test run', () => {
    const input = lineInput('quiet')
    const { container } = render(CanaryLine, { input })
    const model = buildCanaryLineModel(input, 1600)
    expect(container.querySelector('.line-svg .bandlab')?.textContent).toBe(model.name)
    // Self-test ticks: r="3.4" when filled (failed), r="2.8" when hollow.
    expect(container.querySelectorAll('.line-svg circle[r="3.4"], .line-svg circle[r="2.8"]')).toHaveLength(model.selfTestTicks.length)
    // No rise and no failed run on this scene, so the only .bl text is the
    // fortnight's earlier silence labels -- never the bold non-dim kind.
    expect(container.querySelectorAll('.line-svg text.bl:not(.dim)')).toHaveLength(0)
  })

  it('silent: draws the dropped-out curve, dashed tail and sentence', () => {
    const input = lineInput('silent')
    const { container } = render(CanaryLine, { input })
    const model = buildCanaryLineModel(input, 1600)
    expect(model.drop).not.toBeNull()
    const sentenceText = [...container.querySelectorAll('.line-svg text.bl')].find((t) => t.textContent === model.drop!.sentence)
    expect(sentenceText).toBeTruthy()
    // Two silences from the fortnight, each an empty hollow circle (r="3.2") plus a label.
    expect(container.querySelectorAll('.line-svg circle[r="3.2"]')).toHaveLength(model.silenceMarks.length)
    const silenceLabels = [...container.querySelectorAll('.line-svg text.bl.dim')].map((t) => t.textContent)
    for (const mark of model.silenceMarks) expect(silenceLabels).toContain(mark.text)
  })

  it('failed: fills the failed tick and spells the run out above the line', () => {
    const input = lineInput('failed')
    const { container } = render(CanaryLine, { input })
    const model = buildCanaryLineModel(input, 1600)
    expect(model.failedRun).not.toBeNull()
    const filled = container.querySelectorAll('.line-svg circle[fill="var(--ink)"]')
    expect(filled).toHaveLength(1)
    const detail = [...container.querySelectorAll('.line-svg text.bl.dim')].find((t) => t.textContent === model.failedRun!.detail)
    expect(detail).toBeTruthy()
    const lead = [...container.querySelectorAll('.line-svg text.bl')].find((t) => t.textContent?.startsWith(model.failedRun!.lead))
    expect(lead).toBeTruthy()
  })

  it('night: a labelled rise draws its stem and joined text, and the accessible name names the canary', () => {
    const input = lineInput('night')
    const { container } = render(CanaryLine, { input })
    const model = buildCanaryLineModel(input, 1600)
    expect(model.labels.length).toBeGreaterThan(0)
    expect(container.querySelectorAll('.line-svg path[fill="none"][stroke="var(--ink-3)"]').length).toBeGreaterThan(0)
    expect(screen.getByRole('img', { name: new RegExp(`${model.name}: its heartbeat`) })).toBeTruthy()
  })
})
