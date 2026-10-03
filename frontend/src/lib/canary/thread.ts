// The history thread (ADR-0004 rule 4): every state this canary has
// been in, newest first, one line each, with the band's own dots down
// the left. Built from the responses the page already holds -- the state
// history (#56), the self-test runs (#118), the trace's own hits and the
// canary's enrolment -- so a row is never written by hand.
import type { HistoryPeriod, SelfTestRunSummary, TraceHit } from '../types'
import type { Segment } from '../sentence/types'
import { calendarDaysBetween, formatClockShort, relativeDayLabel } from '../sentence/time'
import { numberToWords, plural, wordOrNumber } from '../sentence/words'
import { canaryScene, dateLower, medianGapS } from './sentence'
import {
  canaryOf,
  periodsHere,
  selfTestCards,
  traceOf,
  visitorsHere,
  type CanaryPageInput,
} from './model'

/** Which dot a row carries -- the band's own marks, no new colour:
 * 'ok' a filled green dot, 'fault' a filled ink one, 'live' a hollow
 * ink ring for something still true, 'pend' the hollow dim ring for a
 * state that is neither (issue #47's pending). */
export type ThreadDot = 'ok' | 'fault' | 'live' | 'pend'

export interface ThreadRow {
  key: string
  /** Sort key, ms. */
  at: number
  when: string
  state: string
  detail: Segment[]
  dot: ThreadDot
}

/** "11 min" / "6 min 12 s" / "18 h" / "3 d" -- the thread's own duration
 * voice, which says "min" where the tiles say "m" and stops at the
 * largest unit once a state has run past an hour: a self-test that has
 * been failing since 04:00 has been failing for eighteen hours, and the
 * four extra minutes are not what the reader is weighing. */
export function threadDuration(seconds: number): string {
  const whole = Math.max(0, Math.floor(seconds))
  if (whole < 60) return `${whole} s`
  if (whole < 3600) {
    const m = Math.floor(whole / 60)
    const s = whole % 60
    return s === 0 ? `${m} min` : `${m} min ${s} s`
  }
  if (whole < 86400) return `${Math.floor(whole / 3600)} h`
  return `${Math.floor(whole / 86400)} d`
}

/** "today 04:00" / "thu 3 sep 07:12" / "wed 12 aug" -- the thread's own
 * timestamp column. */
function whenLabel(iso: string, now: string, withClock = true): string {
  const day = relativeDayLabel(iso, now)
  const clock = withClock ? ` ${formatClockShort(iso)}` : ''
  if (day === 'today' || day === 'yesterday') return `${day}${clock}`
  return `${dateLower(iso)}${clock}`
}

/** How many heartbeats a silence of this length swallowed. */
function beatsMissed(seconds: number, intervalS: number): number {
  if (intervalS <= 0) return 0
  return Math.max(1, Math.floor(seconds / intervalS))
}

function silenceRows(input: CanaryPageInput): ThreadRow[] {
  const now = input.trace.now
  const intervalS = input.page.facts.heartbeat_interval_s
  return periodsHere(input)
    .filter((p) => p.state === 'silent')
    .map((period) => {
      const started = Date.parse(period.started_at)
      const ended = period.ended_at === null ? null : Date.parse(period.ended_at)
      const seconds = ((ended ?? Date.parse(now)) - started) / 1000
      const missed = beatsMissed(seconds, intervalS)
      const detail: Segment[] = [
        { text: `${numberToWords(missed)} ${plural(missed, 'heartbeat')} missed` },
      ]
      if (ended === null) {
        detail.push({ text: ' so far. ' }, { text: 'still silent', cls: 'live' })
      } else {
        detail.push({ text: `, back at ${formatClockShort(period.ended_at!)} on its own` })
      }
      return {
        key: `silent:${period.started_at}`,
        at: started,
        when: whenLabel(period.started_at, now),
        state: `silent · ${threadDuration(seconds)}`,
        detail,
        dot: ended === null ? ('live' as const) : ('fault' as const),
      }
    })
}

/** The grade recap the quiet page adds under its self-test row: "ssh,
 * telnet and smb marked, portscan attributed". */
function gradeRecap(input: CanaryPageInput): string {
  const byGrade = new Map<string, string[]>()
  for (const card of selfTestCards(canaryOf(input))) {
    if (card.outcome !== 'passed' || card.grade === null) continue
    const word = card.grade === 'challenge_marked' ? 'challenge-marked' : card.grade
    const list = byGrade.get(word)
    if (list) list.push(card.service)
    else byGrade.set(word, [card.service])
  }
  const clauses: string[] = []
  for (const [grade, services] of byGrade) {
    const names = services.length > 1 ? `${services.slice(0, -1).join(', ')} and ${services[services.length - 1]}` : services[0]
    clauses.push(`${names} ${grade}`)
  }
  return clauses.join(', ')
}

function selfTestRow(input: CanaryPageInput, run: SelfTestRunSummary): ThreadRow | null {
  if (!run.completed_at) return null
  const now = input.trace.now
  const cards = selfTestCards(canaryOf(input))
  const probed = cards.filter((c) => c.outcome !== 'untested').length
  const answered = cards.filter((c) => c.outcome === 'passed').length
  const at = Date.parse(run.completed_at)

  if (run.passed === false) {
    const failed = (run.failed_services ?? []).map((s) => {
      const [service, port] = s.split(/\s+/)
      return port && port !== '0' ? `${service} :${port}` : service
    })
    const others = cards.filter((c) => c.outcome === 'passed').map((c) => c.service)
    const detail: Segment[] = [
      { text: `${failed.join(', ') || 'a service'} did not answer` },
    ]
    if (others.length > 0) {
      const named = others.length > 1 ? `${others.slice(0, -1).join(', ')} and ${others[others.length - 1]}` : others[0]
      detail.push({ text: `; ${named} did` })
    }
    const stillFailing = canaryOf(input).status === 'self_test_failed'
    if (stillFailing) {
      detail.push({ text: '. ' }, { text: 'still failing', cls: 'live' }, { text: ' — no run since' })
    } else {
      detail.push({ text: '.' })
    }
    const forS = (Date.parse(now) - at) / 1000
    return {
      key: `selftest:${run.issued_at}`,
      at,
      when: whenLabel(run.completed_at, now),
      state: stillFailing ? `self-test failed · ${threadDuration(forS)}` : 'self-test failed',
      detail,
      dot: stillFailing ? 'live' : 'fault',
    }
  }

  const detail: Segment[] = [
    { text: `${wordOrNumber(answered)} of ${wordOrNumber(probed)} services answered` },
  ]
  if (canaryScene(input).kind === 'quiet') {
    const recap = gradeRecap(input)
    if (recap) detail.push({ text: ` — ${recap}` })
  }
  return {
    key: `selftest:${run.issued_at}`,
    at,
    when: whenLabel(run.completed_at, now),
    state: 'self-test passed',
    detail,
    dot: 'ok',
  }
}

/** One row per visitor that reached this canary: what it tried, and
 * whether it was part of a walk across the cage. */
function visitorRows(input: CanaryPageInput): ThreadRow[] {
  const now = input.trace.now
  const fleetSize = input.trace.canaries.length
  const hits = traceOf(input)?.hits ?? []
  const rows: ThreadRow[] = []

  for (const visitor of visitorsHere(input)) {
    const own = hits.filter((h) => h.visitor === visitor.source_ip)
    if (own.length === 0) continue
    const newest = own.reduce((a, b) => (Date.parse(b.at) > Date.parse(a.at) ? b : a))
    const at = Date.parse(newest.at)
    const detail: Segment[] = [{ text: visitor.source_ip, cls: 'ip' }]

    if (visitor.kind === 'repeat') {
      const nights = new Set(own.map((h) => h.at.slice(0, 10))).size
      const port = newest.service ? portOfHit(input, newest) : null
      const gap = medianGapS(own)
      detail.push({
        text:
          ` knocks${port ? ` on :${port}` : ''}${gap === null ? '' : ` every ~${Math.max(1, Math.round(gap / 60 / 5) * 5)} min`}` +
          `, ${own.length} ${plural(own.length, 'time')} in ${numberToWords(nights)} ${plural(nights, 'night')}`,
      })
      rows.push({
        key: `visitor:${visitor.source_ip}:${visitor.kind}`,
        at,
        when: nights > 1 ? `${numberToWords(nights)} nights` : whenLabel(newest.at, now),
        state: 'repeat visitor',
        detail,
        dot: 'fault',
      })
      continue
    }

    detail.push({ text: ` tried ${newest.tried || 'a login'} on ${newest.service}` })
    if (visitor.canaries.length > 1) {
      detail.push({
        text: ` — part of a walk across ${visitor.canaries.length === fleetSize ? `all ${wordOrNumber(fleetSize)}` : wordOrNumber(visitor.canaries.length)} canaries`,
      })
    }
    rows.push({
      key: `visitor:${visitor.source_ip}:${visitor.kind}`,
      at,
      when: whenLabel(newest.at, now),
      state: VISIT_STATE[visitor.kind],
      detail,
      dot: 'fault',
    })
  }
  return rows
}

const VISIT_STATE: Record<TraceHit['kind'], string> = {
  sweep: 'swept',
  repeat: 'repeat visitor',
  inside: 'looked at from inside',
  touch: 'touched',
}

function portOfHit(input: CanaryPageInput, hit: TraceHit): string | null {
  for (const part of canaryOf(input).ports.split(' · ')) {
    const [name, port] = part.trim().split(/\s+/)
    if (name === hit.service) return port ?? null
  }
  return null
}

/** The thread's oldest rows: how this canary came to exist. */
function enrolmentRows(input: CanaryPageInput): ThreadRow[] {
  const now = input.trace.now
  const facts = input.page.facts
  const rows: ThreadRow[] = []
  const enrolledAt = Date.parse(facts.enrolled_at)

  if (facts.registered_at) {
    const registeredAt = Date.parse(facts.registered_at)
    const gap = (registeredAt - enrolledAt) / 1000
    rows.push({
      key: 'registered',
      at: registeredAt,
      when: whenLabel(facts.registered_at, now),
      state: 'registered',
      detail: [{ text: `first self-test passed ${threadDuration(gap)} after enrolment` }],
      dot: 'ok',
    })
  }

  const agent = facts.agent_version ? `, mockingbird ${facts.agent_version}` : ''
  rows.push({
    key: 'enrolled',
    at: enrolledAt,
    when: whenLabel(facts.enrolled_at, now),
    state: 'enrolled',
    detail: [
      { text: `on ${canaryOf(input).lane}${agent}` },
      ...(facts.registered_at ? [{ text: ' — pending its first self-test' }] : []),
    ],
    // Hollow: enrolled is not yet a working canary -- it is pending its
    // first self-test, which the row above records passing.
    dot: facts.registered_at ? 'pend' : 'live',
  })
  return rows
}

/** The quiet page's own row: nothing has touched this canary, and the
 * last thing that touched the cage at all was somewhere else. Only the
 * quiet page tells that story -- on every other page something here
 * happened, and the last touch elsewhere is not what the reader came
 * for. */
function quietRow(input: CanaryPageInput): ThreadRow | null {
  const lastHit = input.trace.last_hit
  if (!lastHit || lastHit.canary === canaryOf(input).id) return null
  return {
    key: 'quiet',
    at: Date.parse(lastHit.at),
    when: whenLabel(lastHit.at, input.trace.now, false),
    state: 'quiet',
    detail: [{ text: `the last thing that touched the cage was on ${lastHit.canary}, not here` }],
    dot: 'ok',
  }
}

/** Every state this canary has been in, newest first. */
export function threadRows(input: CanaryPageInput): ThreadRow[] {
  const rows: ThreadRow[] = [...silenceRows(input), ...visitorRows(input), ...enrolmentRows(input)]

  // The newest completed run stands for what the self-test says now;
  // older failures are already in the state history as their own
  // periods, and fourteen "passed" rows would bury everything else.
  const newestRun = input.page.self_test_runs.find((r) => r.completed_at)
  if (newestRun) {
    const row = selfTestRow(input, newestRun)
    if (row) rows.push(row)
  }
  for (const period of periodsHere(input)) {
    if (period.state !== 'self_test_failed' || period.ended_at === null) continue
    rows.push(closedTestFailureRow(period, input))
  }

  if (canaryScene(input).kind === 'quiet') {
    const quiet = quietRow(input)
    if (quiet) rows.push(quiet)
  }

  return rows.sort((a, b) => b.at - a.at)
}

function closedTestFailureRow(period: HistoryPeriod, input: CanaryPageInput): ThreadRow {
  const started = Date.parse(period.started_at)
  const seconds = (Date.parse(period.ended_at!) - started) / 1000
  return {
    key: `test-failed:${period.started_at}`,
    at: started,
    when: whenLabel(period.started_at, input.trace.now),
    state: `self-test failed · ${threadDuration(seconds)}`,
    detail: [{ text: `cleared at ${formatClockShort(period.ended_at!)}` }],
    dot: 'fault',
  }
}

/** "enrolled 24 days ago · nothing earlier" -- the thread's closing
 * line, which says the thread is complete rather than truncated. */
export function threadFooter(input: CanaryPageInput): string {
  const days = calendarDaysBetween(input.page.facts.enrolled_at, input.trace.now)
  return `enrolled ${days} ${plural(days, 'day')} ago · nothing earlier`
}
