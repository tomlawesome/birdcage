// The hero + sub sentence, issue #38's four rules in priority order.
// Every value that Canary/Visitor actually carries is computed from the
// fixture data; the one clause with no field to compute it from (rule
// 4's "last touch before this window") is documented in quietStory.ts.
import type { Canary, Range, Visitor } from '../types'
import { agoWords } from './duration'
import { formatClock } from './time'
import { canariesPhrase, minutesPhrase, rangeNoun, servicesNarrative, triedNarrative } from './narrative'
import { DEFAULT_QUIET_STORY, computeQuietDays, type QuietStory } from './quietStory'
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

function rule2(silent: Canary, canaries: Canary[], now: string, story: QuietStory): SentenceResult {
  const days = computeQuietDays(now, story)
  const otherCount = canaries.length - 1
  return {
    rule: 2,
    hero: [
      { text: 'Quiet for ' },
      { text: `${days} days`, bold: true, cls: 'ok' },
      { text: ' — but ' },
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

function rule4(canaries: Canary[], now: string, story: QuietStory): SentenceResult {
  const days = computeQuietDays(now, story)
  const newest = canaries.reduce((a, b) =>
    new Date(b.last_heartbeat_at ?? 0) > new Date(a.last_heartbeat_at ?? 0) ? b : a,
  )
  const newestAgoS = Math.max(
    0,
    Math.round((new Date(now).getTime() - new Date(newest.last_heartbeat_at ?? now).getTime()) / 1000),
  )
  return {
    rule: 4,
    hero: [{ text: 'Quiet for ' }, { text: `${days} days`, bold: true, cls: 'ok' }, { text: '.' }],
    sub: [
      { text: 'Nothing has touched a canary since ' },
      { text: story.lastTouchDateLabel, bold: true },
      { text: ` — ${story.lastTouchPrefix}` },
      { text: story.lastTouchIp, cls: 'ip' },
      { text: `${story.lastTouchSuffix} ` },
      {
        text: `The ${wordOrNumber(canaries.length)} canaries have phoned home every minute since; the newest heartbeat was ${agoWords(newestAgoS)}.`,
      },
    ],
  }
}

export function computeSentence(
  canaries: Canary[],
  visitors: Visitor[],
  range: Range,
  now: string,
  story: QuietStory = DEFAULT_QUIET_STORY,
): SentenceResult {
  const arriving = visitors.find((v) => v.kind === 'sweep' && v.still_arriving)
  if (arriving) return rule1(arriving, canaries, visitors, range, now)

  const silent = canaries.find((c) => c.status === 'silent')
  if (silent) return rule2(silent, canaries, now, story)

  if (visitors.length > 0) return rule3(visitors, canaries, range)

  return rule4(canaries, now, story)
}
