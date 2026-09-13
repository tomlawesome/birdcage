import { calendarDaysBetween } from './time'
import type { LastHit } from '../types'

// Rule 4's sub ("Nothing has touched a canary since Thu 13 Aug -- one
// touch on canary-guest :23 from 198.51.100.200.") and rule 2's "Quiet
// for 23 days" both name the last thing that ever touched a canary,
// which -- since it can fall outside every range GET /api/trace serves --
// only /api/trace's own last_hit field can answer (issue #39). This
// module turns that field into the words the sentences above need;
// buildQuietStory returns null when last_hit is null (the alerts table
// has never held a row), and every caller falls back to its own
// shortest wording for that case rather than guessing a date.
export interface QuietStory {
  lastTouchAt: string
  lastTouchDateLabel: string
  lastTouchPrefix: string
  lastTouchIp: string
  lastTouchSuffix: string
}

const WEEKDAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

/** "Thu 13 Aug" (UTC, matching every other date this module and its
 * callers format). */
function dateLabel(iso: string): string {
  const d = new Date(iso)
  return `${WEEKDAYS[d.getUTCDay()]} ${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]}`
}

/** How the last touch reads before its ip, by kind -- "one touch on X"
 * is the only case a fixture exercises, but a genuinely last-ever hit
 * could be any kind, so each gets the same verb rule3 already uses for
 * the same four kinds (lib/sentence/rules.ts). */
const KIND_PREFIX: Record<LastHit['kind'], string> = {
  touch: 'one touch on',
  repeat: 'a repeat knock on',
  inside: 'a look from inside at',
  sweep: 'a sweep that reached',
}

/** Builds the quiet-day story from trace.last_hit. Null in, null out --
 * callers use that to pick their own "nothing has ever touched a
 * canary" wording instead of a date-shaped sentence with no date. */
export function buildQuietStory(lastHit: LastHit | null): QuietStory | null {
  if (!lastHit) return null
  return {
    lastTouchAt: lastHit.at,
    lastTouchDateLabel: dateLabel(lastHit.at),
    lastTouchPrefix: `${KIND_PREFIX[lastHit.kind]} ${lastHit.canary} :${lastHit.port} from `,
    lastTouchIp: lastHit.visitor,
    lastTouchSuffix: '.',
  }
}

/** Days between the story's last touch and `now` -- 0 when story is
 * null (no last touch to count from; callers avoid showing this number
 * in that case rather than reading 0 as meaningful). */
export function computeQuietDays(now: string, story: QuietStory | null): number {
  if (!story) return 0
  return calendarDaysBetween(story.lastTouchAt, now)
}
