import { describe, expect, it } from 'vitest'
import { sceneInput, type SceneName } from '../canary/fixtures'
import { silences, traceOf } from '../canary/model'
import { buildCanaryLineModel, LINE_Y, type CanaryLineInput } from './single'

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

const model = (scene: SceneName) => buildCanaryLineModel(lineInput(scene), 1600)

describe('the line itself', () => {
  it('runs the full width when the canary is phoning home', () => {
    const m = model('quiet')
    expect(m.xTo).toBe(m.x1)
    expect(m.drop).toBeNull()
    expect(m.y).toBe(LINE_Y)
  })

  it('stops at the last heartbeat when it is silent, and hangs the drop below', () => {
    const m = model('silent')
    expect(m.drop).not.toBeNull()
    expect(m.xTo).toBeLessThan(m.x1)
    expect(m.xTo).toBe(m.drop!.xs)
    expect(m.drop!.yd).toBe(LINE_Y + 22)
    expect(m.drop!.sentence).toBe('dropped out · last heartbeat 21:58:19 · silent 6 m 12 s')
  })
})

describe('the fortnight\'s earlier silences', () => {
  it('marks each one, oldest label highest, and never marks the open one', () => {
    const m = model('silent')
    expect(m.silenceMarks).toHaveLength(2)
    expect(m.silenceMarks[0].text).toBe('tue 1 sep · silent 11 min')
    expect(m.silenceMarks[1].text).toBe('thu 3 sep · silent 1 min')
    expect(m.silenceMarks[0].labelY).toBeLessThan(m.silenceMarks[1].labelY)
    expect(m.silenceMarks.every((s) => s.labelX < s.x)).toBe(true)
  })

  it('keeps the marks but drops their labels when a rise is labelled on the same line', () => {
    const m = model('night')
    expect(m.silenceMarks).toHaveLength(2)
    expect(m.silenceMarks.map((s) => s.text)).toEqual(['', ''])
    expect(m.labels.length).toBeGreaterThan(0)
  })
})

describe('self-test marks', () => {
  it('one tick per run, under the line', () => {
    const m = model('quiet')
    expect(m.selfTestTicks).toHaveLength(14)
    expect(m.selfTestTicks.every((t) => !t.failed)).toBe(true)
    expect(m.failedRun).toBeNull()
  })

  it('a failed run is filled, and spelled out above the line', () => {
    const m = model('failed')
    expect(m.selfTestTicks.filter((t) => t.failed)).toHaveLength(1)
    expect(m.failedRun).not.toBeNull()
    expect(m.failedRun!.lead).toBe('self-test 04:00 · ')
    expect(m.failedRun!.failed).toBe('telnet did not answer')
    expect(m.failedRun!.detail).toBe('portscan, smb, ssh answered · next run 04:00 tomorrow')
    // Above the line, where a visitor's words go; the tick itself stays
    // under it.
    expect(m.failedRun!.y1).toBeLessThan(LINE_Y)
    expect(m.failedRun!.stemTop).toBeLessThan(LINE_Y)
  })
})

describe('rises at this page\'s own scale', () => {
  it('a sweep takes the ADR\'s full 60px, and the ripples are taller than the band\'s', () => {
    const m = model('night')
    const sweep = m.bumps.find((b) => b.kind === 'sweep' && b.labelled)!
    expect(sweep.h).toBeGreaterThanOrEqual(60)
    expect(m.bumps.filter((b) => !b.labelled).every((b) => b.h === 22)).toBe(true)
  })

  it('a quiet canary has no rises at all', () => {
    expect(model('quiet').bumps).toEqual([])
  })
})

describe('the axis and the brink', () => {
  it('sits where the band\'s does, measured from the line', () => {
    const m = model('quiet')
    expect(m.axisY).toBe(LINE_Y + 42)
    expect(m.brink.x).toBe(m.x1)
    expect(m.brink.yTop).toBe(LINE_Y - 110)
    expect(m.brink.yBottom).toBe(LINE_Y + 40)
    expect(m.now.text).toBe('NOW · 22:04:31')
    expect(m.axisTicks.map((t) => t.label)).toEqual(['15 m', '1 h', '24 h', '14 d'])
  })
})
