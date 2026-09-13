// Port of gen.py's axis(): the segment-boundary ticks ("14 d", "24 h",
// "1 h", "15 m"), the NOW label, the day-boundary ticks with weekday-date
// captions every 4th, and the two span captions ("23 hours, compressed",
// "the last quarter hour, stretched").
//
// gen.py only ever renders the 14d case (the concept's data story is
// always a 14-day window); the day/week tick counts below for 1h/24h/90d
// are this port's generalisation for issue #37's other range chips, not
// pixel-tested against a shot the way the 14d fixtures are.
import { cx, type Seg } from './segments'
import { formatDate } from './format'

export interface AxisTick {
  x: number
  label: string
}

export interface DayTick {
  x: number
  label: string | null
}

export interface Caption {
  x: number
  text: string
}

const DAY = 86400

const BOUNDARY_LABEL: Record<number, string> = {
  900: '15 m',
  3600: '1 h',
  86400: '24 h',
  1209600: '14 d',
  7776000: '90 d',
}

/** One tick per active segment boundary -- for 14d this is gen.py's four ticks exactly. */
export function axisTicks(segs: Seg[], x0: number, x1: number): AxisTick[] {
  return segs
    .map((seg) => ({ x: cx(seg.to, segs, x0, x1), label: BOUNDARY_LABEL[seg.to] }))
    .filter((t): t is AxisTick => Boolean(t.label))
}

export function nowLabel(now: Date, x1: number): { x: number; text: string } {
  const hh = String(now.getUTCHours()).padStart(2, '0')
  const mm = String(now.getUTCMinutes()).padStart(2, '0')
  const ss = String(now.getUTCSeconds()).padStart(2, '0')
  return { x: x1, text: `NOW · ${hh}:${mm}:${ss}` }
}

/** How many midnight ticks to draw, and which are labelled with a date. */
function dayTickCount(segs: Seg[]): { count: number; labelEvery: number } {
  const hasFortnight = segs.some((s) => s.to === 1209600)
  const hasNinetyDays = segs.some((s) => s.to === 7776000)
  if (hasNinetyDays) return { count: 90, labelEvery: 12 }
  if (hasFortnight) return { count: 14, labelEvery: 4 }
  if (segs.some((s) => s.to === 86400)) return { count: 1, labelEvery: 1 }
  return { count: 0, labelEvery: 1 }
}

/** Port of gen.py's `for k in range(14): x = cx(NOW + k*86400)` -- NOW there
 * is seconds-since-midnight, so NOW+k*86400 is the ago-distance to midnight
 * k days back; this reproduces that with a real Date. */
export function dayTicks(now: Date, segs: Seg[], x0: number, x1: number): DayTick[] {
  const secsSinceMidnight = now.getUTCHours() * 3600 + now.getUTCMinutes() * 60 + now.getUTCSeconds()
  const { count, labelEvery } = dayTickCount(segs)
  const out: DayTick[] = []
  for (let k = 0; k < count; k++) {
    const ago = secsSinceMidnight + k * DAY
    const x = cx(ago, segs, x0, x1)
    let label: string | null = null
    if (k > 0 && k % labelEvery === 0) {
      const d = new Date(now.getTime() - k * DAY * 1000)
      label = formatDate(d)
    }
    out.push({ x, label })
  }
  return out
}

/** The two fixed captions gen.py draws below the axis ticks. */
export function axisCaptions(segs: Seg[], x0: number, x1: number): Caption[] {
  const out: Caption[] = []
  const hasHour = segs.some((s) => s.to === 3600)
  const hasDay = segs.some((s) => s.to === 86400)
  if (hasHour && hasDay) {
    out.push({ x: (cx(86400, segs, x0, x1) + cx(3600, segs, x0, x1)) / 2, text: '23 hours, compressed' })
  }
  out.push({ x: (cx(900, segs, x0, x1) + x1) / 2, text: 'the last quarter hour, stretched' })
  return out
}
