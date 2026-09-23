// The canary page's own sentences (issue #118, round 7 direction O):
// the crumb above the hero, the hero and sub, the footer line, and the
// actions the state earns. Same shape as lib/sentence's fleet rules --
// segments, never HTML -- and the same voice; what changes is the
// subject. The fleet page speaks about a cage; this one speaks about one
// canary, so "the other three are fine" has no place here and "it" does.
import type { Canary, TraceHit, Visitor, VisitorKind } from '../types'
import type { Segment } from '../sentence/types'
import { agoWords, durationCoarse, durationExact } from '../sentence/duration'
import { calendarDaysBetween, formatClock, formatClockShort, relativeDayLabel } from '../sentence/time'
import { canariesPhrase, triedNarrative } from '../sentence/narrative'
import { numberToWords, plural, wordOrNumber } from '../sentence/words'
import {
  canaryOf,
  lastCompletedRun,
  periodsHere,
  selfTestCards,
  silences,
  traceOf,
  visitorsHere,
  type CanaryPageInput,
  type Silence,
} from './model'

const WEEKDAYS_SHORT = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat']
const MONTHS_SHORT = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec']

/** "sat 5 sep" -- the crumb's and the thread's lowercase date. */
export function dateLower(iso: string): string {
  const d = new Date(iso)
  return `${WEEKDAYS_SHORT[d.getUTCDay()]} ${d.getUTCDate()} ${MONTHS_SHORT[d.getUTCMonth()]}`
}

/** "Wed 12 Aug" -- prose capitalisation, as the hero's sub uses it. */
export function dateProper(iso: string): string {
  const lower = dateLower(iso)
  return lower.replace(/(^|\s)([a-z])/g, (_, lead: string, letter: string) => `${lead}${letter.toUpperCase()}`)
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1)
}

/** Which rule speaks for this page, in the fleet rules' own precedence:
 * a visit in progress first, then the canary's own worst state, then a
 * visit that has finished, then quiet. */
export type CanaryScene =
  | { kind: 'visited'; visitor: Visitor; hit: TraceHit }
  | { kind: 'state'; status: Canary['status'] }
  | { kind: 'quiet' }

function newestHitOf(input: CanaryPageInput, visitor: Visitor): TraceHit | null {
  const hits = (traceOf(input)?.hits ?? []).filter((h) => h.visitor === visitor.source_ip)
  if (hits.length === 0) return null
  return hits.reduce((a, b) => (Date.parse(b.at) > Date.parse(a.at) ? b : a))
}

/** The loudest visitor on this canary: a still-arriving sweep first,
 * else whichever reached it most recently. */
function leadVisitor(input: CanaryPageInput): Visitor | null {
  const here = visitorsHere(input)
  return here.find((v) => v.kind === 'sweep' && v.still_arriving) ?? here[0] ?? null
}

export function canaryScene(input: CanaryPageInput): CanaryScene {
  const canary = canaryOf(input)
  const visitor = leadVisitor(input)
  const hit = visitor ? newestHitOf(input, visitor) : null

  if (visitor && hit && visitor.kind === 'sweep' && visitor.still_arriving) {
    return { kind: 'visited', visitor, hit }
  }
  if (canary.status !== 'ok') return { kind: 'state', status: canary.status }
  if (visitor && hit) return { kind: 'visited', visitor, hit }
  return { kind: 'quiet' }
}

// ---------------------------------------------------------------- crumb

/** "the cage › canary-iot · sat 5 sep · 22:04:31", or the state / the
 * night's counts in place of the clock -- gen.py's GRP line. The canary
 * name carries the lane colour class every mention of it does. */
export function canaryCrumb(input: CanaryPageInput): Segment[] {
  const canary = canaryOf(input)
  const now = input.trace.now
  const lead: Segment[] = [
    { text: 'the cage › ' },
    { text: canary.name, cls: 'c' },
    { text: ` · ${dateLower(now)}` },
  ]

  const scene = canaryScene(input)
  if (scene.kind === 'visited') {
    const hitsToday = (traceOf(input)?.hits ?? []).filter((h) => calendarDaysBetween(h.at, now) === 0).length
    const flagged = visitorsHere(input).filter((v) => v.kind === 'sweep' && v.still_arriving).length
    const out = [...lead]
    if (flagged > 0) out.push({ text: ' · ' }, { text: `${flagged} flagged`, cls: 'r' })
    out.push({ text: ` · ${hitsToday} hits today` })
    return out
  }
  if (scene.kind === 'state') {
    return [...lead, { text: ' · ' }, { text: stateWords(canary), bold: true }]
  }
  return [...lead, { text: ` · ${formatClock(now)}` }]
}

/** The crumb's and the status strip's short words for a state -- the
 * tile's voice, not the hero's. */
function stateWords(c: Canary): string {
  switch (c.status) {
    case 'silent':
      return `silent ${durationExact(c.silent_for_s ?? 0)}`
    case 'self_test_failed':
      return 'self-test failed'
    case 'token_conflict':
      return `token conflict ${durationCoarse(c.token_conflict_for_s ?? 0)}`
    case 'not_delivering':
      return 'not delivering'
    case 'throttled':
      return `throttled ${durationCoarse(c.throttled_for_s ?? 0)}`
    case 'rotation_stalled':
      return `rotation stalled ${durationCoarse(c.rotation_stalled_for_s ?? 0)}`
    case 'pending':
      return 'pending its first self-test'
    default:
      return 'ok'
  }
}

// ---------------------------------------------------------------- hero + sub

export interface CanarySentence {
  hero: Segment[]
  sub: Segment[]
}

const VISIT_VERB: Record<VisitorKind, string> = {
  sweep: 'swept at',
  repeat: 'knocked on at',
  inside: 'browsed from inside at',
  touch: 'touched at',
}

/** How the self-test run reads in prose: "this morning's", "today's",
 * "yesterday's", or the date. */
function runPossessive(at: string, now: string): string {
  const days = calendarDaysBetween(at, now)
  if (days === 0) return new Date(at).getUTCHours() < 12 ? "this morning's" : "today's"
  if (days === 1) return "yesterday's"
  return `${dateProper(at)}'s`
}

/** "ssh, smb and the portscan lure" -- the services a run reached, with
 * a lure named as one so the list does not read as five open ports. */
function reachedNarrative(input: CanaryPageInput): string {
  const names = selfTestCards(canaryOf(input))
    .filter((card) => card.outcome === 'passed')
    .map((card) => (card.lure ? `the ${card.service} lure` : card.service))
  if (names.length === 0) return 'none of its services'
  if (names.length === 1) return names[0]
  return `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`
}

/** "telnet :23" -- the store's "service dest_port" strings, said the way
 * the rest of the page says a port. */
function failedNarrative(services: string[]): string {
  if (services.length === 0) return 'one of its services'
  const named = services.map((s) => {
    const [service, port] = s.split(/\s+/)
    return port && port !== '0' ? `${service} :${port}` : service
  })
  if (named.length === 1) return named[0]
  return `${named.slice(0, -1).join(', ')} and ${named[named.length - 1]}`
}

function quietSentence(input: CanaryPageInput): CanarySentence {
  const canary = canaryOf(input)
  const facts = input.page.facts
  const now = input.trace.now
  const run = lastCompletedRun(input.page.self_test_runs)
  const reached = selfTestCards(canary).filter((c) => c.outcome === 'passed').length
  const beatAgo = canary.last_heartbeat_at
    ? Math.max(0, Math.round((Date.parse(now) - Date.parse(canary.last_heartbeat_at)) / 1000))
    : null

  const sub: Segment[] = [
    { text: 'Nothing has touched it since it was enrolled on ' },
    { text: dateProper(facts.enrolled_at), bold: true },
    { text: `. It phones home every ${intervalWords(facts.heartbeat_interval_s)}` },
  ]
  if (beatAgo !== null) sub.push({ text: ` — the last heartbeat was ${agoWords(beatAgo)} —` })
  if (run?.completed_at) {
    sub.push({ text: ` and ${runPossessive(run.completed_at, now)} self-test at ` })
    sub.push({ text: formatClockShort(run.completed_at), bold: true })
    sub.push({ text: ` reached all ${wordOrNumber(reached)} of its services.` })
  } else {
    sub.push({ text: '. No self-test has completed yet.' })
  }
  const recent = recentSilences(input)
  if (recent.length > 0) sub.push({ text: ` ${silenceRecap(recent)}` })

  return {
    hero: [
      { text: canary.name, cls: 'c' },
      { text: ' is quiet, and ' },
      { text: 'answers when tested', bold: true, cls: 'ok' },
      { text: '.' },
    ],
    sub,
  }
}

/** "every minute" / "every 5 minutes" -- the heartbeat interval as the
 * page says it. */
export function intervalWords(seconds: number): string {
  if (seconds === 60) return 'minute'
  if (seconds % 60 === 0) return `${wordOrNumber(seconds / 60)} minutes`
  return `${wordOrNumber(seconds)} seconds`
}

/** The silences inside the last week -- what "two short silences this
 * week" counts. */
function recentSilences(input: CanaryPageInput): Silence[] {
  const now = Date.parse(input.trace.now)
  return silences(input).filter((s) => now - Date.parse(s.startedAt) <= 7 * 86400_000)
}

/** "Two short silences this week, both over in minutes." */
function silenceRecap(recent: Silence[]): string {
  const n = recent.length
  const allShort = recent.every((s) => !s.open && s.seconds < 3600)
  const short = allShort ? 'short ' : ''
  const tail = allShort ? (n === 1 ? ', over in minutes' : n === 2 ? ', both over in minutes' : ', all over in minutes') : ''
  return `${capitalize(numberToWords(n))} ${short}${plural(n, 'silence')} this week${tail}.`
}

function selfTestFailedSentence(input: CanaryPageInput): CanarySentence {
  const canary = canaryOf(input)
  const now = input.trace.now
  const failed = canary.self_test_failed_services ?? []
  const at = canary.last_self_test_at ?? now
  const ports = failed.length === 1 ? 'that port' : 'those ports'

  const sub: Segment[] = [
    { text: `${capitalize(runPossessive(at, now))} self-test at ` },
    { text: formatClockShort(at), bold: true },
    { text: ` reached ${reachedNarrative(input)}; ` },
    { text: `${failedNarrative(failed)} did not answer`, bold: true },
    {
      text:
        `. The agent is fine and the box is up, so a visitor on ${ports} would go unseen. ` +
        'Run the test again after looking at the box',
    },
  ]
  sub.push({ text: nextRunClause(input.page.facts.self_test_schedule, now) })

  return {
    hero: [
      { text: canary.name, cls: 'c' },
      { text: ' is phoning home — but ' },
      { text: `deaf on ${deafOn(failed)}.`, bold: true },
    ],
    sub,
  }
}

/** "telnet" / "telnet and smb" -- the hero's shortest naming of what did
 * not answer, service names only (the sub carries the ports). */
function deafOn(failed: string[]): string {
  const names = failed.map((s) => s.split(/\s+/)[0])
  if (names.length === 0) return 'one of its services'
  if (names.length === 1) return names[0]
  return `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`
}

/** "; the next scheduled run is 04:00 tomorrow." -- a schedule the page
 * can name, or a full stop when the self-test is switched off. */
function nextRunClause(schedule: string, now: string): string {
  if (!schedule) return '.'
  const [hh, mm] = schedule.split(':').map(Number)
  const d = new Date(now)
  const todayAt = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate(), hh, mm)
  const when = todayAt > Date.parse(now) ? 'today' : 'tomorrow'
  return `; the next scheduled run is ${schedule} ${when}.`
}

function silentSentence(input: CanaryPageInput): CanarySentence {
  const canary = canaryOf(input)
  const now = input.trace.now
  const all = silences(input)
  const earlier = all.filter((s) => !s.open)
  const total = all.length

  const sub: Segment[] = [
    { text: 'Its last heartbeat was ' },
    { text: formatClock(canary.last_heartbeat_at ?? now), bold: true },
    { text: `, ${agoWords(canary.silent_for_s ?? 0)}.` },
  ]
  if (earlier.length > 0) {
    // Oldest first: the reader is being shown a run of silences
    // building up to now, which only reads as one in that order.
    const ordered = [...earlier].reverse()
    sub.push({ text: ' It also dropped out on ' })
    ordered.forEach((s, i) => {
      if (i > 0) sub.push({ text: i === ordered.length - 1 ? ' and on ' : ', on ' })
      sub.push({ text: dateProper(s.startedAt), bold: true })
      // The unit is said once: "for eleven minutes and on Thu 3 Sep for
      // one" -- repeating it makes a list of dates read as a table.
      sub.push({ text: ` for ${i === 0 ? minutesWords(s.seconds) : numberToWords(Math.max(1, Math.round(s.seconds / 60)))}` })
    })
    sub.push({ text: `, and came back on its own ${ordered.length === 1 ? 'that time' : 'both times'}.` })
  }
  sub.push({ text: ` ${silentVerdict(total, all, now)}` })

  return {
    hero: [
      { text: canary.name, cls: 'c' },
      { text: ' is silent — ' },
      { text: `${ordinalTimeThisWeek(total)}.`, bold: true },
    ],
    sub,
  }
}

/** "eleven minutes" / "one" -- a silence's length in the sub's prose
 * voice, where the second and later clauses drop the unit ("for eleven
 * minutes and on Thu 3 Sep for one"). */
function minutesWords(seconds: number): string {
  const m = Math.max(1, Math.round(seconds / 60))
  return `${numberToWords(m)} ${plural(m, 'minute')}`
}

/** "the third time this week" -- how the hero names a repeat silence,
 * and "silent" plainly when it is the first. */
function ordinalTimeThisWeek(total: number): string {
  const ORDINALS = ['', 'first', 'second', 'third', 'fourth', 'fifth', 'sixth', 'seventh', 'eighth', 'ninth']
  if (total <= 1) return 'and nothing has come back yet'
  const word = ORDINALS[total] ?? `${total}th`
  return `the ${word} time this week`
}

/** The closing verdict: a run of silences is the router or the host, a
 * single one is a bad minute. */
function silentVerdict(total: number, all: Silence[], now: string): string {
  if (total < 3) {
    return (
      'A silent canary is not the quiet we want — the host may be down, or its firewall rule on the router may ' +
      'have moved.'
    )
  }
  const oldest = all[all.length - 1]
  // Inclusive: Tuesday to Saturday is five days, not the four a
  // subtraction gives -- this clause counts days that had a silence in
  // them, so both ends are days.
  const days = Math.max(1, calendarDaysBetween(oldest.startedAt, now) + 1)
  return (
    `${capitalize(numberToWords(total))} silences in ${numberToWords(days)} days is not a bad minute: ` +
    'the host, or its rule on the router, wants looking at.'
  )
}

function stateSentence(input: CanaryPageInput, status: Canary['status']): CanarySentence {
  const canary = canaryOf(input)
  switch (status) {
    case 'silent':
      return silentSentence(input)
    case 'self_test_failed':
      return selfTestFailedSentence(input)
    case 'token_conflict':
      return {
        hero: [{ text: canary.name, cls: 'c' }, { text: "'s revoked token came back.", bold: true }],
        sub: [
          { text: 'It was presented ' },
          { text: agoWords(canary.token_conflict_for_s ?? 0), bold: true },
          {
            text:
              ', while its successor was already active. Either the token was stolen and the thief rotated first, ' +
              'or two boxes share one identity. ',
          },
          { text: 'Look at the box now.', bold: true },
        ],
      }
    case 'not_delivering':
      return {
        hero: [{ text: canary.name, cls: 'c' }, { text: ' is not delivering.', bold: true }],
        sub: [
          {
            text:
              "Its heartbeats arrive on time, but its agent can't read OpenCanary's log, so whatever it catches " +
              'never reaches this page — which would read just the same if it were catching someone right now. ',
          },
          { text: 'Check the agent on the box.', bold: true },
        ],
      }
    case 'throttled':
      return {
        hero: [{ text: canary.name, cls: 'c' }, { text: ' is throttled.', bold: true }],
        sub: [
          { text: 'It crossed its rate limit ' },
          { text: agoWords(canary.throttled_for_s ?? 0), bold: true },
          {
            text:
              ' and birdcage refused part of what it sent — delay, not loss: the events wait in its log. Either its ' +
              'agent is broken, or this box is under an attack larger than anything planned for. ',
          },
          { text: 'Go and see which.', bold: true },
        ],
      }
    case 'rotation_stalled':
      return {
        hero: [{ text: canary.name, cls: 'c' }, { text: "'s token rotation has stalled.", bold: true }],
        sub: [
          canary.rotation_stalled_escalated
            ? { text: "It hasn't completed a rotation in over a day." }
            : { text: `Birdcage issued it a fresh token ${agoWords(canary.rotation_stalled_for_s ?? 0)} and the agent hasn't picked it up.` },
          {
            text:
              ' It still phones home on the old token — nothing is being missed, but a protection has quietly ' +
              'lapsed. ',
          },
          { text: 'Check the agent.', bold: true },
        ],
      }
    default:
      return {
        hero: [{ text: canary.name, cls: 'c' }, { text: ' is pending its first self-test.', bold: true }],
        sub: [
          { text: 'It was provisioned on ' },
          { text: dateProper(input.page.facts.enrolled_at), bold: true },
          {
            text:
              ' and has not yet proved a round trip end to end. It is not a fault: until the first self-test passes, ' +
              'birdcage has nothing to claim about it either way.',
          },
        ],
      }
  }
}

/** Seconds between consecutive hits, median -- the honest cadence for
 * "every twenty minutes", where dividing the whole span by the count
 * would be pulled out of shape by the nights in between. */
export function medianGapS(hits: TraceHit[]): number | null {
  if (hits.length < 2) return null
  const times = hits.map((h) => Date.parse(h.at)).sort((a, b) => a - b)
  const gaps: number[] = []
  for (let i = 1; i < times.length; i++) gaps.push((times[i] - times[i - 1]) / 1000)
  gaps.sort((a, b) => a - b)
  return gaps[Math.floor(gaps.length / 2)]
}

/** "every twenty minutes" from a median gap, rounded to the nearest
 * five minutes -- a knock every 1198 seconds is a knock every twenty
 * minutes, and saying "every 19.97 minutes" claims a precision the
 * clocks involved do not have. */
function cadenceWords(gapS: number): string {
  const minutes = Math.max(1, Math.round(gapS / 60 / 5) * 5)
  if (minutes >= 60 && minutes % 60 === 0) {
    const h = minutes / 60
    return `every ${numberToWords(h)} ${plural(h, 'hour')}`
  }
  return `every ${numberToWords(minutes)} ${plural(minutes, 'minute')}`
}

function visitedSentence(input: CanaryPageInput, visitor: Visitor, hit: TraceHit): CanarySentence {
  const canary = canaryOf(input)
  const fleetSize = input.trace.canaries.length
  const traceHits = traceOf(input)?.hits ?? []
  const repeat = visitorsHere(input).find((v) => v.kind === 'repeat' && v.source_ip !== visitor.source_ip)

  const sub: Segment[] = [
    { text: visitor.source_ip, cls: 'ip' },
    { text: ' tried ' },
    // The literal credential, not triedNarrative's "default passwords":
    // on the fleet page that clause summarises a walk across four
    // canaries, here it is the one thing this visitor typed at this
    // canary, and the operator wants to see it.
    { text: hit.tried || triedNarrative(visitor.tried), bold: true },
    { text: ` on ${hit.service} at ${formatClockShort(hit.at)}` },
  ]
  if (visitor.canaries.length > 1) {
    sub.push({ text: ` — the same address that walked ${canariesPhrase(visitor.canaries.length, fleetSize)} tonight` })
  }
  sub.push({ text: '. ' })

  if (repeat) {
    const repeatHits = traceHits.filter((h) => h.visitor === repeat.source_ip)
    const gap = medianGapS(repeatHits)
    const nights = new Set(repeatHits.map((h) => h.at.slice(0, 10))).size
    const port = repeatHits[0] ? portOf(canary, repeatHits[0].service) : null
    sub.push({ text: 'Underneath it, ' })
    sub.push({ text: repeat.source_ip, cls: 'ip' })
    sub.push({
      text:
        ` has knocked${port ? ` on :${port}` : ''}${gap === null ? '' : ` ${cadenceWords(gap)}`}` +
        `${nights > 1 ? ` for ${numberToWords(nights)} nights` : ''}. `,
    })
  }
  sub.push({ text: 'Nothing here blocks: ' })
  sub.push({ text: 'lookback in mikroview ▸', bold: true })
  sub.push({ text: ' to act.' })

  const stillKnocking = repeat !== undefined || visitor.still_arriving
  return {
    hero: [
      { text: canary.name, cls: 'c' },
      { text: ' was ' },
      { text: `${VISIT_VERB[visitor.kind]} ${formatClockShort(hit.at)}`, bold: true, cls: 'r' },
      { text: stillKnocking ? ', and is still being knocked on.' : '.' },
    ],
    sub,
  }
}

function portOf(canary: Canary, service: string): string | null {
  for (const part of canary.ports.split(' · ')) {
    const [name, port] = part.trim().split(/\s+/)
    if (name === service) return port ?? null
  }
  return null
}

export function canarySentence(input: CanaryPageInput): CanarySentence {
  const scene = canaryScene(input)
  if (scene.kind === 'visited') return visitedSentence(input, scene.visitor, scene.hit)
  if (scene.kind === 'state') return stateSentence(input, scene.status)
  return quietSentence(input)
}

// ---------------------------------------------------------------- footer

export function canaryFooter(input: CanaryPageInput): Segment[] {
  const canary = canaryOf(input)
  const now = input.trace.now
  const scene = canaryScene(input)
  const days = calendarDaysBetween(input.page.facts.enrolled_at, now)

  if (scene.kind === 'visited') {
    return [
      { text: `a quiet ${quietSpanWords(input, scene.visitor.kind)} until ` },
      { text: formatClockShort(scene.hit.at), bold: true },
      { text: ' tonight — ' },
      { text: 'the address walking the cage reached this one too', cls: 'r' },
    ]
  }
  if (scene.kind === 'state' && scene.status === 'silent') {
    const total = silences(input).length
    const oldest = silences(input)[silences(input).length - 1]
    const span = oldest ? Math.max(1, calendarDaysBetween(oldest.startedAt, now) + 1) : 1
    return [
      { text: `${numberToWords(total)} ${plural(total, 'silence')} in ${numberToWords(span)} ${plural(span, 'day')}`, bold: true },
      { text: ' — silence is only good news while the heartbeat keeps coming' },
    ]
  }
  if (scene.kind === 'state' && scene.status === 'self_test_failed') {
    const failed = canary.self_test_failed_services ?? []
    return [
      { text: 'phoning home, delivering, ' },
      { text: `deaf on ${failed.length === 1 ? 'one port' : `${wordOrNumber(failed.length)} ports`}`, bold: true },
      { text: ' — a canary that cannot hear a visitor is no canary on that port' },
    ]
  }
  if (scene.kind === 'state') {
    return [
      { text: `${numberToWords(days)} days on the ${canary.lane} lane · ` },
      { text: stateWords(canary), bold: true },
      { text: ' — quiet is only good news while the cage is sound' },
    ]
  }
  return [
    { text: `${numberToWords(days)} days on the ${canary.lane} lane · ` },
    { text: 'answers when tested', cls: 'ok' },
    { text: ' · nothing to act on' },
  ]
}

/** "three weeks" -- how long this canary had been untouched before the
 * visit the footer is about. */
function quietSpanWords(input: CanaryPageInput, kind: VisitorKind): string {
  const now = input.trace.now
  // How long since the last visit of the same kind: a footer about
  // tonight's sweep is measuring the quiet a sweep broke, and the
  // repeat visitor knocking away underneath it never broke that quiet.
  const earlier = (traceOf(input)?.hits ?? []).filter((h) => h.kind === kind && calendarDaysBetween(h.at, now) > 0)
  const since =
    earlier.length > 0
      ? earlier.reduce((a, b) => (Date.parse(b.at) > Date.parse(a.at) ? b : a)).at
      : input.page.facts.enrolled_at
  const days = Math.max(0, calendarDaysBetween(since, now))
  if (days >= 14) return `${numberToWords(Math.round(days / 7))} weeks`
  if (days >= 7) return 'a week'
  return `${numberToWords(days)} ${plural(days, 'day')}`
}

// ---------------------------------------------------------------- actions

export interface CanaryAction {
  label: string
  /** A quiet pill is an action the state has not earned but that is
   * still available -- gen.py's `.pill.quiet`. */
  quiet: boolean
}

/** The actions the state earns (ADR-0004 rule 5): run the self-test now,
 * lookback in mikroview, raw lines, mark as maintenance. Each appears
 * only where it would do something -- a silent canary cannot be probed,
 * and there is nothing to look back at on a canary nothing has touched.
 * Nothing here is wired to a handler yet; the page shows what the state
 * earns, and the issues that implement each action fill them in. */
export function canaryActions(input: CanaryPageInput): CanaryAction[] {
  const canary = canaryOf(input)
  const scene = canaryScene(input)
  const hits = traceOf(input)?.hits ?? []
  const out: CanaryAction[] = []

  if (scene.kind === 'visited') {
    out.push({ label: 'lookback in mikroview ▸', quiet: false })
    if (hits.length > 0) out.push({ label: 'raw lines ▸', quiet: false })
    // Reachable, but not what this page is about right now.
    if (canary.status !== 'silent') out.push({ label: 'run the self-test now', quiet: true })
    return out
  }

  if (canary.status !== 'silent') out.push({ label: 'run the self-test now ▸', quiet: false })
  if (canary.status !== 'ok' || hits.length > 0) out.push({ label: 'lookback in mikroview ▸', quiet: false })
  out.push({ label: 'mark as maintenance', quiet: true })
  return out
}

// ---------------------------------------------------------------- ledger heading

/** "self-test · today 04:00:07 · passed · 4 of 4", plus "· no run since
 * it went silent" when the canary has been silent since the last run. */
export interface SelfTestHeading {
  lead: string
  verdict: { text: string; cls: string } | null
  tail: string
  /** Said in bold after the counts, when there is something the counts
   * do not say on their own. */
  note: string
}

export function selfTestHeading(input: CanaryPageInput): SelfTestHeading {
  const canary = canaryOf(input)
  const now = input.trace.now
  const run = lastCompletedRun(input.page.self_test_runs)
  if (!run?.completed_at) {
    return { lead: 'self-test · ', verdict: { text: 'never run', cls: 'r' }, tail: '', note: '' }
  }
  const cards = selfTestCards(canary)
  const probed = cards.filter((c) => c.outcome !== 'untested')
  const passed = probed.filter((c) => c.outcome === 'passed')
  const ok = run.passed === true
  const at = `${relativeDayLabel(run.completed_at, now)} ${formatClock(run.completed_at)}`

  let note = ''
  if (canary.status === 'silent' && canary.last_heartbeat_at && Date.parse(run.completed_at) < Date.parse(canary.last_heartbeat_at)) {
    note = 'no run since it went silent'
  }
  return {
    lead: `self-test · ${at} · `,
    verdict: { text: ok ? 'passed' : 'failed', cls: ok ? 'ok' : 'r' },
    tail: ` · ${passed.length} of ${probed.length}`,
    note,
  }
}
