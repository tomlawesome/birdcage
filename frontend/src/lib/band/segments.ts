// Port of gen.py's axis math (docs/design/concepts/round-6/gen.py, `cx`).
// Keep the numbers: the segment table below is SEGS verbatim, and cx()'s
// loop is the same walk-back-from-X1 the generator uses. The generator
// only ever draws the 14d case; the per-range table here (segmentsForRange)
// generalises it the way issue #37 asks for -- 15m all stretched, 1h/24h/14d
// truncating the table, 90d appending one more segment the same width as
// the 24h->14d one.
import type { Range } from '../types'

export interface Seg {
  from: number
  to: number
  width: number
}

const MIN = 60
const HOUR = 3600
const DAY = 86400
const FORTNIGHT = 14 * DAY
const NINETY_DAYS = 90 * DAY

// gen.py: SEGS = [(0, 900, 300), (900, 3600, 180), (3600, 86400, 200), (86400, 1209600, 200)]
export const BASE_SEGS: Seg[] = [
  { from: 0, to: 15 * MIN, width: 300 },
  { from: 15 * MIN, to: HOUR, width: 180 },
  { from: HOUR, to: DAY, width: 200 },
  { from: DAY, to: FORTNIGHT, width: 200 },
]

export function segmentsForRange(range: Range): Seg[] {
  switch (range) {
    case '15m':
      // "all stretched": one segment spanning the whole width. The width
      // number is arbitrary (cx normalises by the sum of segment widths),
      // 300 just keeps it the same order of magnitude as the others.
      return [{ from: 0, to: 15 * MIN, width: 300 }]
    case '1h':
      return BASE_SEGS.slice(0, 2)
    case '24h':
      return BASE_SEGS.slice(0, 3)
    case '14d':
      return BASE_SEGS.slice(0, 4)
    case '90d':
      // "adds a segment 14d->90d at the same width as the 1d->14d one"
      return [...BASE_SEGS, { from: FORTNIGHT, to: NINETY_DAYS, width: BASE_SEGS[3].width }]
  }
}

export function scaleFor(segs: Seg[], x0: number, x1: number): number {
  const total = segs.reduce((sum, seg) => sum + seg.width, 0)
  return (x1 - x0) / total
}

/** Port of gen.py's cx(ago): walk segments back from X1, scaling by SC. */
export function cx(ago: number, segs: Seg[], x0: number, x1: number): number {
  const sc = scaleFor(segs, x0, x1)
  let x = x1
  for (const seg of segs) {
    if (ago <= seg.to) {
      return x - ((ago - seg.from) / (seg.to - seg.from)) * seg.width * sc
    }
    x -= seg.width * sc
  }
  return x0
}
