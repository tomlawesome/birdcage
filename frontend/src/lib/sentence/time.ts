// Every timestamp in the API and the fixtures is UTC ("...Z"); formatting
// with the UTC getters (not the local ones) keeps a rendered clock the
// same in CI as on a laptop in any timezone -- vitest.config.ts also pins
// TZ=UTC for the same reason.
function pad2(n: number): string {
  return String(n).padStart(2, '0')
}

/** "21:58:19" */
export function formatClock(iso: string): string {
  const d = new Date(iso)
  return `${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())}:${pad2(d.getUTCSeconds())}`
}

/** "21:58" */
export function formatClockShort(iso: string): string {
  const d = new Date(iso)
  return `${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())}`
}

function utcMidnight(d: Date): number {
  return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate())
}

/** Whole calendar days between two instants (UTC dates), b - a. */
export function calendarDaysBetween(a: string | Date, b: string | Date): number {
  const da = typeof a === 'string' ? new Date(a) : a
  const db = typeof b === 'string' ? new Date(b) : b
  return Math.round((utcMidnight(db) - utcMidnight(da)) / 86_400_000)
}

export function isSameUTCDate(a: string | Date, b: string | Date): boolean {
  return calendarDaysBetween(a, b) === 0
}

/** "today" / "yesterday" / "N days ago" -- gen.py's EVENTS_NIGHT touch row
 * ("yesterday<small>03:18:40</small>") is the only tested case. */
export function relativeDayLabel(at: string, now: string): string {
  const days = calendarDaysBetween(at, now)
  if (days <= 0) return 'today'
  if (days === 1) return 'yesterday'
  return `${days} days ago`
}
