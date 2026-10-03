import { describe, expect, it } from 'vitest'
import { cx, segmentsForRange } from './segments'

const X0 = 190
const X1 = 1520

describe('cx (issue #37)', () => {
  it('places the right edge at "now" for every range', () => {
    for (const range of ['15m', '1h', '24h', '14d', '90d'] as const) {
      expect(cx(0, segmentsForRange(range), X0, X1)).toBeCloseTo(X1, 5)
    }
  })

  it('14d: matches gen.py at the segment boundaries (X0=190, X1=1520, SC=(X1-X0)/880)', () => {
    const segs = segmentsForRange('14d')
    const sc = (X1 - X0) / 880
    expect(cx(900, segs, X0, X1)).toBeCloseTo(X1 - 300 * sc, 5)
    expect(cx(3600, segs, X0, X1)).toBeCloseTo(X1 - 480 * sc, 5)
    expect(cx(86400, segs, X0, X1)).toBeCloseTo(X1 - 680 * sc, 5)
    expect(cx(1209600, segs, X0, X1)).toBeCloseTo(X0, 5)
  })

  it('is continuous across a segment boundary (both sides agree)', () => {
    const segs = segmentsForRange('14d')
    // ago=900 is the boundary between the stretched and 1h segments; the
    // function must return the same x whichever segment "claims" it.
    const justBefore = cx(899.999, segs, X0, X1)
    const atBoundary = cx(900, segs, X0, X1)
    expect(Math.abs(justBefore - atBoundary)).toBeLessThan(0.5)
  })

  it('15m is all stretched: the whole width covers 0..900s', () => {
    const segs = segmentsForRange('15m')
    expect(cx(0, segs, X0, X1)).toBeCloseTo(X1, 5)
    expect(cx(900, segs, X0, X1)).toBeCloseTo(X0, 5)
  })

  it('1h ends its table at the 1h boundary', () => {
    const segs = segmentsForRange('1h')
    expect(cx(3600, segs, X0, X1)).toBeCloseTo(X0, 5)
  })

  it('24h ends its table at the 24h boundary', () => {
    const segs = segmentsForRange('24h')
    expect(cx(86400, segs, X0, X1)).toBeCloseTo(X0, 5)
  })

  it('90d appends a segment the same width as 1d->14d, ending at 90 days', () => {
    const segs = segmentsForRange('90d')
    expect(segs).toHaveLength(5)
    expect(segs[4].width).toBe(segs[3].width)
    expect(segs[4].to).toBe(90 * 86400)
    expect(cx(90 * 86400, segs, X0, X1)).toBeCloseTo(X0, 5)
  })
})
