// The hero + sub sentence, issue #38's four rules in priority order.
// Every value that Canary/Visitor actually carries is computed from the
// fixture data; the one clause with no field to compute it from (rule
// 4's "last touch before this window") is documented in quietStory.ts.
//
// Issue #45 widens rule 2 from "any silent canary" into the health
// slot: the fleet's worst-ranked state (token conflict, silent, not
// delivering, throttled, rotation stalled -- health.go's order) speaks
// there, each with its own copy in #38's voice. The slot itself does
// not move: a still-arriving sweep still outranks it, exactly as it
// already outranked silent, and rules 3 and 4 still only run when
// every canary is 'ok', so the quiet page gains no words.
import type { Canary, CanaryStatus, LastHit, Range, Visitor } from '../types'
import { agoWords } from './duration'
import { formatClock } from './time'
import { canariesPhrase, minutesPhrase, rangeNoun, servicesNarrative, triedNarrative } from './narrative'
import { buildQuietStory, computeQuietDays } from './quietStory'
import { wordOrNumber } from './words'
import type { Segment } from './types'

export interface SentenceResult {
  rule: 1 | 2 | 3 | 4
  hero: Segment[]
  sub: Segment[]
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1)
}

function weekday(iso: string): string {
  return new Intl.DateTimeFormat('en-US', { weekday: 'long', timeZone: 'UTC' }).format(new Date(iso))
}

function rule1(visitor: Visitor, canaries: Canary[], visitors: Visitor[], range: Range, now: string): SentenceResult {
  const total = canaries.length
  const touched = visitor.canaries.length
  const minutes = Math.max(0, Math.round((new Date(now).getTime() - new Date(visitor.first_at).getTime()) / 60_000))
  const services = servicesNarrative(visitor.services)
  const tried = triedNarrative(visitor.tried)
  const more = visitors.length - 1
  return {
    rule: 1,
    hero: [{ text: 'One address is walking the cage.', bold: true, cls: 'r' }],
    sub: [
      { text: visitor.source_ip, cls: 'ip' },
      { text: ' has reached ' },
      { text: `${canariesPhrase(touched, total)} in ${minutesPhrase(minutes)}`, bold: true },
      { text: ' — ' },
      { text: `${services}, ${tried}` },
      { text: ' — and is still arriving. ' },
      { text: `${capitalize(wordOrNumber(more))} more visitor${more === 1 ? '' : 's'} in the ${rangeNoun(range)}. ` },
      { text: 'Nothing here blocks: ' },
      { text: 'lookback in mikroview ▸', bold: true },
      { text: ' to act.' },
    ],
  }
}

/** Rule 2's opener -- "Quiet for 23 days — but " when there is a last
 * touch to count from, else just the contrast (never "Quiet for 0
 * days"). Issue #45's states inherit this shape rather than each
 * inventing an opener: the quiet page against the one canary that is
 * wrong is the contrast #38 chose for silent. */
function quietBut(now: string, lastHit: LastHit | null): Segment[] {
  const story = buildQuietStory(lastHit)
  if (!story) return [{ text: 'Nothing has touched a canary — but ' }]
  return [
    { text: 'Quiet for ' },
    { text: `${computeQuietDays(now, story)} days`, bold: true, cls: 'ok' },
    { text: ' — but ' },
  ]
}

/** Rule 2 closes "The other three are fine." For the #45 states that
 * clause is earned, not automatic: it appears only when every other
 * canary really is 'ok' -- with an ordered enum two can be wrong at
 * once, the hero speaks for the worst, and the rest show on their own
 * tiles -- and it covers the fleets the silent fixture never sees: one
 * canary (no clause) and two ("is", not "are"). */
function othersFine(canaries: Canary[], self: Canary): Segment[] {
  const others = canaries.filter((c) => c !== self)
  if (others.length === 0 || others.some((c) => c.status !== 'ok')) return []
  const n = others.length
  return [{ text: ` The other ${wordOrNumber(n)} ${n === 1 ? 'is' : 'are'} fine.` }]
}

function rule2(silent: Canary, canaries: Canary[], now: string, lastHit: LastHit | null): SentenceResult {
  const otherCount = canaries.length - 1
  return {
    rule: 2,
    hero: [
      ...quietBut(now, lastHit),
      { text: `${silent.name} is silent.`, bold: true },
    ],
    sub: [
      { text: 'Its last heartbeat was ' },
      { text: formatClock(silent.last_heartbeat_at ?? now), bold: true },
      {
        text:
          `, ${agoWords(silent.silent_for_s ?? 0)}; it phones home every minute. A silent canary is not the quiet ` +
          `we want — the host may be down, or its firewall rule on the router may have moved. The other ` +
          `${wordOrNumber(otherCount)} are fine.`,
      },
    ],
  }
}

// The #45 states below share rule 2's slot and shape: quietBut opener,
// bold state clause; sub = the concrete fact first (with its duration
// bold, as rule 2 bolds the heartbeat clock), what it means in plain
// words, the operator's next step in bold (as rule 1 bolds "lookback in
// mikroview ▸"), then othersFine when it is true. Each keeps to what
// birdcage actually knows -- health.go's comments draw the lines
// (throttled is delay, not loss; not-delivering is the agent's own
// log-read report; rotation-stalled has two triggers the frontend
// cannot tell apart except through `escalated`).

/** Token conflict: a revoked token was presented while its successor is
 * active (#45 state 7) -- the one state whose next step is "look at the
 * box now". */
function rule2TokenConflict(c: Canary, canaries: Canary[], now: string, lastHit: LastHit | null): SentenceResult {
  return {
    rule: 2,
    hero: [...quietBut(now, lastHit), { text: `${c.name}'s revoked token came back.`, bold: true }],
    sub: [
      { text: 'It was presented ' },
      { text: agoWords(c.token_conflict_for_s ?? 0), bold: true },
      {
        text:
          ', while its successor was already active. Either the token was stolen and the thief rotated first, ' +
          'or two boxes share one identity. ',
      },
      { text: 'Look at the box now.', bold: true },
      ...othersFine(canaries, c),
    ],
  }
}

/** Not delivering: the agent's own self-report says its log read is
 * failing while its heartbeats are fine (#45 state 3) -- the page would
 * read quiet whatever the canary caught, which is #45's founding case. */
function rule2NotDelivering(c: Canary, canaries: Canary[], now: string, lastHit: LastHit | null): SentenceResult {
  return {
    rule: 2,
    hero: [...quietBut(now, lastHit), { text: `${c.name} is not delivering.`, bold: true }],
    sub: [
      {
        text:
          "Its heartbeats arrive on time, but its agent can't read OpenCanary's log, so whatever the canary " +
          'catches never reaches this page — which would read just the same if the canary were catching someone ' +
          'right now. ',
      },
      { text: 'Check the agent on the box.', bold: true },
      ...othersFine(canaries, c),
    ],
  }
}

/** Throttled: the canary crossed its rate limit within the last few
 * minutes and birdcage refused part of what it sent (#45 state 2,
 * corrected: with a retrying agent a refusal is delay, not loss -- it
 * stays critical as an under-attack signal, not as missed hits). */
function rule2Throttled(c: Canary, canaries: Canary[], now: string, lastHit: LastHit | null): SentenceResult {
  return {
    rule: 2,
    hero: [...quietBut(now, lastHit), { text: `${c.name} is throttled.`, bold: true }],
    sub: [
      { text: 'It crossed its rate limit ' },
      { text: agoWords(c.throttled_for_s ?? 0), bold: true },
      {
        text:
          ' and birdcage refused part of what it sent — delay, not loss: the events wait in its log. Either its ' +
          'agent is broken, or that box is under an attack larger than anything planned for. ',
      },
      { text: 'Go and see which.', bold: true },
      ...othersFine(canaries, c),
    ],
  }
}

/** Rotation stalled (#45 state 4, degraded): two triggers share this
 * state, and only `escalated` separates them here. Fresh can only be
 * the issued-but-unused token, so it may say so; escalated may be that
 * signal past a day or a rotation that was never asked for at all, so
 * it claims only what both make true -- no completed rotation in over a
 * day. Either way the canary itself is fine, or a worse state would
 * have outranked this one, so "nothing is being missed" holds. */
function rule2RotationStalled(c: Canary, canaries: Canary[], now: string, lastHit: LastHit | null): SentenceResult {
  const opening: Segment[] = c.rotation_stalled_escalated
    ? [{ text: "It hasn't completed a rotation in over a day." }]
    : [
        { text: 'Birdcage issued it a fresh token ' },
        { text: agoWords(c.rotation_stalled_for_s ?? 0), bold: true },
        { text: " and the agent hasn't picked it up." },
      ]
  return {
    rule: 2,
    hero: [...quietBut(now, lastHit), { text: `${c.name}'s token rotation has stalled.`, bold: true }],
    sub: [
      ...opening,
      {
        text:
          ' It still phones home every minute on the old token — nothing is being missed, but a protection has ' +
          'quietly lapsed. ',
      },
      { text: 'Check the agent.', bold: true },
      ...othersFine(canaries, c),
    ],
  }
}

/** No fixture or shot covers this state; the issue gives only an example
 * shape ("One address swept all four on {day}; {ip} keeps knocking on
 * {canary} :{port}."), so this builds one line per visitor kind present
 * rather than reproducing a literal transcript. Covered by a hand-built
 * test (issue #38), not a pixel comparison. */
function rule3(visitors: Visitor[], canaries: Canary[], range: Range): SentenceResult {
  const byId = new Map(canaries.map((c) => [c.id, c]))
  const kinds: Visitor['kind'][] = ['sweep', 'repeat', 'inside', 'touch']
  const lines: string[] = []
  for (const kind of kinds) {
    const matches = visitors.filter((v) => v.kind === kind)
    if (matches.length === 0) continue
    const v = matches.reduce((a, b) => (new Date(b.last_at) > new Date(a.last_at) ? b : a))
    const canary = byId.get(v.canaries[0]?.id ?? '')
    const canaryName = canary?.name ?? v.canaries[0]?.id ?? 'a canary'
    const port = canary ? (canary.ports.match(new RegExp(`${v.services[0]}\\s+(\\S+)`)) ?? [])[1] : undefined
    if (kind === 'sweep') {
      lines.push(`One address swept ${canariesPhrase(v.canaries.length, canaries.length)} on ${weekday(v.last_at)}.`)
    } else if (kind === 'repeat') {
      lines.push(`${v.source_ip} keeps knocking on ${canaryName}${port ? ` :${port}` : ''}.`)
    } else if (kind === 'inside') {
      lines.push(`${v.source_ip} browsed ${canaryName}${port ? ` :${port}` : ''} from inside.`)
    } else {
      lines.push(`${v.source_ip} touched ${canaryName}${port ? ` :${port}` : ''}, once.`)
    }
  }
  return {
    rule: 3,
    hero: [
      {
        text: `${capitalize(wordOrNumber(visitors.length))} visitor${visitors.length === 1 ? '' : 's'} in the ${rangeNoun(range)}, none tonight.`,
      },
    ],
    sub: lines.map((text, i) => ({ text: i === 0 ? text : ` ${text}` })),
  }
}

// Worst-first display rank over the ordered health enum -- mirrors
// internal/store/health.go's healthStateRank the same way status.ts
// does (duplicated, not shared: a display ordering over an API
// response, not database logic).
const HEALTH_RANK: Record<CanaryStatus, number> = {
  token_conflict: 0,
  silent: 1,
  not_delivering: 2,
  throttled: 3,
  rotation_stalled: 4,
  ok: 5,
}

function worstCanary(canaries: Canary[]): Canary | null {
  let worst: Canary | null = null
  for (const c of canaries) {
    if (c.status === 'ok') continue
    if (!worst || HEALTH_RANK[c.status] < HEALTH_RANK[worst.status]) worst = c
  }
  return worst
}

function rule4(canaries: Canary[], now: string, lastHit: LastHit | null): SentenceResult {
  const newest = canaries.reduce((a, b) =>
    new Date(b.last_heartbeat_at ?? 0) > new Date(a.last_heartbeat_at ?? 0) ? b : a,
  )
  const newestAgoS = Math.max(
    0,
    Math.round((new Date(now).getTime() - new Date(newest.last_heartbeat_at ?? now).getTime()) / 1000),
  )
  const phonedHome = `The ${wordOrNumber(canaries.length)} canaries have phoned home every minute since; the newest heartbeat was ${agoWords(newestAgoS)}.`

  const story = buildQuietStory(lastHit)
  if (!story) {
    // No alert has ever been recorded -- shortest wording consistent
    // with rule4's voice, since there is no date to build "quiet for N
    // days" or "since {date}" from (issue #39).
    return {
      rule: 4,
      hero: [{ text: 'Nothing has ever touched a canary.' }],
      sub: [{ text: phonedHome }],
    }
  }

  const days = computeQuietDays(now, story)
  return {
    rule: 4,
    hero: [{ text: 'Quiet for ' }, { text: `${days} days`, bold: true, cls: 'ok' }, { text: '.' }],
    sub: [
      { text: 'Nothing has touched a canary since ' },
      { text: story.lastTouchDateLabel, bold: true },
      { text: ` — ${story.lastTouchPrefix}` },
      { text: story.lastTouchIp, cls: 'ip' },
      { text: `${story.lastTouchSuffix} ` },
      { text: phonedHome },
    ],
  }
}

export function computeSentence(
  canaries: Canary[],
  visitors: Visitor[],
  range: Range,
  now: string,
  lastHit: LastHit | null = null,
): SentenceResult {
  const arriving = visitors.find((v) => v.kind === 'sweep' && v.still_arriving)
  if (arriving) return rule1(arriving, canaries, visitors, range, now)

  // Rule 2, widened by #45: the fleet's worst-ranked unhealthy canary
  // speaks, in health.go's order. The slot is where silent always sat
  // -- below a still-arriving sweep, above the visitor recap and the
  // quiet story -- and each state carries its own copy.
  const worst = worstCanary(canaries)
  if (worst) {
    switch (worst.status) {
      case 'token_conflict':
        return rule2TokenConflict(worst, canaries, now, lastHit)
      case 'silent':
        return rule2(worst, canaries, now, lastHit)
      case 'not_delivering':
        return rule2NotDelivering(worst, canaries, now, lastHit)
      case 'throttled':
        return rule2Throttled(worst, canaries, now, lastHit)
      case 'rotation_stalled':
        return rule2RotationStalled(worst, canaries, now, lastHit)
    }
  }

  if (visitors.length > 0) return rule3(visitors, canaries, range)

  return rule4(canaries, now, lastHit)
}
