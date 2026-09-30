// The footer sentence per state (issue #38 / gen.py's three `.foot`
// strings). Its day count always spells the number out in full, even
// past nine (the issue's own example: "twenty-three quiet days" here vs.
// "23 days" in the hero).
import type { Canary, LastHit, Range, Visitor } from '../types'
import { worstCanary } from './rules'
import { formatClockShort } from './time'
import { rangeNoun } from './narrative'
import { buildQuietStory, computeQuietDays } from './quietStory'
import { numberToWords, wordOrNumber } from './words'
import type { Segment } from './types'

export function computeFooter(
  canaries: Canary[],
  visitors: Visitor[],
  range: Range,
  now: string,
  lastHit: LastHit | null = null,
): Segment[] {
  const arriving = visitors.find((v) => v.kind === 'sweep' && v.still_arriving)
  if (arriving) {
    return [
      { text: `a quiet ${rangeNoun(range)} until ` },
      { text: formatClockShort(arriving.first_at), bold: true },
      { text: ' tonight — ' },
      { text: 'one address is walking the cage right now', cls: 'r' },
    ]
  }

  const days = computeQuietDays(now, buildQuietStory(lastHit))
  const worst = worstCanary(canaries)
  if (worst?.status === 'silent') {
    const silentCount = canaries.filter((c) => c.status === 'silent').length
    const silentPhrase =
      silentCount === 1 ? 'one agent has stopped talking' : `${wordOrNumber(silentCount)} agents have stopped talking`
    return [
      { text: `${numberToWords(days)} quiet days · ` },
      { text: silentPhrase, bold: true },
      { text: ' — silence is only good news while the heartbeat keeps coming' },
    ]
  }

  // issue #45: the footer may not call the page clean while a health
  // state is live -- "nothing to act on" was false under a live token
  // conflict. One short summary clause, not a second hero: the count
  // (or the one name), then where to look first when the worst state
  // is the look-now one, in the alarm colour the night footer already
  // uses for its own act-now clause.
  if (worst) {
    // Issue #155: pending is not a fault, so it does not swell this
    // count even when a real fault is what earned this branch.
    const n = canaries.filter((c) => c.status !== 'ok' && c.status !== 'pending').length
    const attention =
      n === 1 ? `${worst.name} needs attention` : `${wordOrNumber(n)} agents need attention`
    // ADR-0012 Part B (#130): credential_conflict is ranked with
    // token_conflict (same red severity, never auto-cleared), so it
    // earns the same act-now tail here.
    const tail: Segment[] =
      worst.status === 'token_conflict' || worst.status === 'credential_conflict'
        ? [{ text: ' — ' }, { text: n === 1 ? 'look at the box now' : `look at ${worst.name} first`, cls: 'r' }]
        : [{ text: ' — quiet is only good news while the cage is sound' }]
    return [{ text: `${numberToWords(days)} quiet days · ` }, { text: attention, bold: true }, ...tail]
  }

  // Issue #155: worstCanary excludes 'pending', so a fleet whose only
  // non-ok canaries are still registering reaches here with worst still
  // null. Name them, but neutrally -- registering is not a fault, so
  // this gets none of the "needs attention" wording above.
  const registering = canaries.filter((c) => c.status === 'pending')
  if (registering.length > 0) {
    const names = registering.map((c) => c.name)
    const namesPhrase =
      names.length === 1 ? names[0] : `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`
    return [
      { text: `${numberToWords(days)} quiet days · ` },
      { text: `${namesPhrase} ${names.length === 1 ? 'is' : 'are'} still registering`, bold: true },
    ]
  }

  if (visitors.length > 0) {
    return [
      { text: 'no sweep tonight · ' },
      { text: `${wordOrNumber(visitors.length)} visitor${visitors.length === 1 ? '' : 's'}`, bold: true },
      { text: ` in the ${rangeNoun(range)}` },
    ]
  }

  const okCount = canaries.filter((c) => c.status === 'ok').length
  return [
    { text: `${numberToWords(days)} quiet days · ` },
    { text: `all ${wordOrNumber(okCount)} phoning home`, cls: 'ok' },
    { text: ' · nothing to act on' },
  ]
}
