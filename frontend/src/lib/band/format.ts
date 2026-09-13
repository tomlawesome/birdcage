// Label copy (issue #37): line 1 is "tried" joined by " · "; line 2 is
// "source -> canary[ :port] · time", time as "21:55", "yesterday 03:18" or
// a date. All times are UTC -- the fixtures' timestamps are UTC and the
// dashboard has no timezone picker yet (same assumption App.svelte makes).

// Well-known canary service -> port, matching the ports strings gen.py's
// data story uses (docs/design/concepts/round-6/gen.py `ports`). The trace
// endpoint's hits carry a service name but no port; this is the minimum
// lookup needed to render " :port" without also fetching /api/canaries.
const SERVICE_PORT: Record<string, number> = {
  ssh: 22,
  http: 80,
  https: 443,
  smb: 445,
  mysql: 3306,
  ftp: 21,
  telnet: 23,
}

export function formatClock(d: Date): string {
  const hh = String(d.getUTCHours()).padStart(2, '0')
  const mm = String(d.getUTCMinutes()).padStart(2, '0')
  return `${hh}:${mm}`
}

export function formatClockWithSeconds(d: Date): string {
  const ss = String(d.getUTCSeconds()).padStart(2, '0')
  return `${formatClock(d)}:${ss}`
}

const WEEKDAYS = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat']
const MONTHS = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec']

/** gen.py's day.strftime('%a %-d %b').lower(), e.g. "fri 12 sep". */
export function formatDate(d: Date): string {
  return `${WEEKDAYS[d.getUTCDay()]} ${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]}`
}

function utcDateKey(d: Date): number {
  return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate())
}

/** Line 2's time: "21:55" today, "yesterday 03:18" yesterday, else the date. */
export function formatEventTime(at: Date, now: Date): string {
  const dayDiff = (utcDateKey(now) - utcDateKey(at)) / 86400000
  if (dayDiff === 0) return formatClock(at)
  if (dayDiff === 1) return `yesterday ${formatClock(at)}`
  return formatDate(at)
}

export function formatDuration(seconds: number): string {
  const m = Math.floor(seconds / 60)
  const s = Math.floor(seconds % 60)
  return m > 0 ? `${m} m ${s} s` : `${s} s`
}

/** Line 1's text (the "✱ " prefix is drawn separately, in the kind colour, same split as gen.py's label()). */
export function joinTried(tried: string[]): string {
  const seen = new Set<string>()
  const out: string[] = []
  for (const t of tried) {
    if (!seen.has(t)) {
      seen.add(t)
      out.push(t)
    }
  }
  return out.join(' · ')
}

/** Line 2: "source -> canary-id[ :port] · time". */
export function buildLine2(sourceIp: string, canaryId: string, service: string, at: Date, now: Date): string {
  const port = SERVICE_PORT[service]
  const portSuffix = port ? ` :${port}` : ''
  return `${sourceIp} → ${canaryId}${portSuffix} · ${formatEventTime(at, now)}`
}
