// The footer sentence per state (issue #38 / gen.py's three `.foot`
// strings). Its day count always spells the number out in full, even
// past nine (the issue's own example: "twenty-three quiet days" here vs.
// "23 days" in the hero).
import type { Canary, LastHit, Range, Visitor } from '../types'
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
  const silent = canaries.find((c) => c.status === 'silent')
  if (silent) {
    const silentCount = canaries.filter((c) => c.status === 'silent').length
    const silentPhrase =
      silentCount === 1 ? 'one canary has stopped talking' : `${wordOrNumber(silentCount)} canaries have stopped talking`
    return [
      { text: `${numberToWords(days)} quiet days · ` },
      { text: silentPhrase, bold: true },
      { text: ' — silence is only good news while the heartbeat keeps coming' },
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
