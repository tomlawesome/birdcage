import { afterEach, describe, expect, it, vi } from 'vitest'
import { CAUGHT_SHARE, clampOffset, makeTrace, seeded, startBars } from './bars'

describe('seeded', () => {
  it('repeats for the same seed', () => {
    const a = seeded(42)
    const b = seeded(42)
    for (let i = 0; i < 50; i++) expect(a()).toBe(b())
  })
  it('differs for another seed', () => {
    const a = Array.from({ length: 10 }, ((r) => () => r())(seeded(1)))
    const b = Array.from({ length: 10 }, ((r) => () => r())(seeded(2)))
    expect(a).not.toEqual(b)
  })
  it('stays in [0, 1) and is not constant', () => {
    const r = seeded(20261115)
    const vals = Array.from({ length: 2000 }, () => r())
    for (const v of vals) {
      expect(v).toBeGreaterThanOrEqual(0)
      expect(v).toBeLessThan(1)
    }
    expect(new Set(vals).size).toBeGreaterThan(1000)
  })
})

describe('makeTrace', () => {
  it.each([0, 5, 20])('every value within ±(3 + reach) for reach %i', (reach) => {
    const t = makeTrace(seeded(7), 400, reach)
    expect(t).toBeInstanceOf(Float32Array)
    expect(t.length).toBe(400)
    for (const v of t) expect(Math.abs(v)).toBeLessThanOrEqual(3 + reach)
  })
  it('at least a third of the values are exactly 0', () => {
    for (const seed of [1, 2, 3, 99]) {
      const t = makeTrace(seeded(seed), 300, 10)
      const zeros = Array.from(t).filter((v) => v === 0).length
      expect(zeros).toBeGreaterThanOrEqual(100)
    }
  })
  it('is not all zeros', () => {
    const t = makeTrace(seeded(5), 300, 10)
    expect(Array.from(t).some((v) => v !== 0)).toBe(true)
  })
  it('the same rnd sequence gives the same trace', () => {
    expect(Array.from(makeTrace(seeded(11), 120, 8))).toEqual(Array.from(makeTrace(seeded(11), 120, 8)))
  })
  it('another sequence gives another trace', () => {
    expect(Array.from(makeTrace(seeded(11), 120, 8))).not.toEqual(Array.from(makeTrace(seeded(12), 120, 8)))
  })
})

describe('clampOffset', () => {
  it('never goes beyond ±62', () => {
    for (const idx of [0, 2, 3, 5]) {
      for (const side of [-1, 1]) {
        expect(clampOffset(500, idx, side)).toBeLessThanOrEqual(62)
        expect(clampOffset(-500, idx, side)).toBeGreaterThanOrEqual(-62)
      }
    }
    expect(clampOffset(500, 1, 1)).toBeLessThanOrEqual(62)
    expect(clampOffset(-500, 1, -1)).toBeGreaterThanOrEqual(-62)
  })
  it('leaves values inside the limits alone', () => {
    expect(clampOffset(10, 0, 1)).toBe(10)
    expect(clampOffset(-10, 0, -1)).toBe(-10)
    expect(clampOffset(-62, 3, 1)).toBe(-62)
  })
  it('barIndex 1 is limited to 36 towards the form', () => {
    // left of the form (side -1): towards the form is positive v
    expect(clampOffset(60, 1, -1)).toBe(36)
    // right of the form (side +1): towards the form is negative v
    expect(clampOffset(-60, 1, 1)).toBe(-36)
  })
  it('barIndex 1 may still move up to 62 away from the form', () => {
    expect(clampOffset(-60, 1, -1)).toBe(-60)
    expect(clampOffset(60, 1, 1)).toBe(60)
    expect(clampOffset(-500, 1, -1)).toBe(-62)
  })
  it('barIndex 1 values within 36 towards the form are unchanged', () => {
    expect(clampOffset(30, 1, -1)).toBe(30)
    expect(clampOffset(-30, 1, 1)).toBe(-30)
  })
  it('barIndex 2 is not limited to 36 towards the form', () => {
    expect(clampOffset(60, 2, -1)).toBe(60)
    expect(clampOffset(-60, 2, 1)).toBe(-60)
  })
})

describe('CAUGHT_SHARE', () => {
  it('is 0.27', () => expect(CAUGHT_SHARE).toBe(0.27))
})

describe('startBars', () => {
  afterEach(() => vi.unstubAllGlobals())

  function motion(reduced: boolean) {
    vi.stubGlobal(
      'matchMedia',
      vi.fn((q: string) => ({ matches: reduced && q.includes('reduce'), media: q, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {}, onchange: null, dispatchEvent: () => false })),
    )
  }

  it('under reduced motion requests no animation frame, and returns a stop function', () => {
    motion(true)
    const raf = vi.fn(() => 1)
    vi.stubGlobal('requestAnimationFrame', raf)
    const stop = startBars(document.createElement('canvas'))
    expect(raf).not.toHaveBeenCalled()
    expect(typeof stop).toBe('function')
    stop()
    expect(raf).not.toHaveBeenCalled()
  })

  it('with frozenAt requests no animation frame even when motion is allowed', () => {
    motion(false)
    const raf = vi.fn(() => 1)
    vi.stubGlobal('requestAnimationFrame', raf)
    const stop = startBars(document.createElement('canvas'), { frozenAt: 3 })
    expect(raf).not.toHaveBeenCalled()
    stop()
  })

  it('with motion allowed and no frozenAt it does animate (neighbouring case)', () => {
    motion(false)
    const raf = vi.fn(() => 1)
    vi.stubGlobal('requestAnimationFrame', raf)
    vi.stubGlobal('cancelAnimationFrame', vi.fn())
    const stop = startBars(document.createElement('canvas'))
    expect(raf).toHaveBeenCalled()
    stop()
  })
})
