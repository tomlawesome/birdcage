import { calendarDaysBetween } from './time'

// Rule 4's sub ("Nothing has touched a canary since Thu 13 Aug -- one
// touch on canary-guest :23 from 198.51.100.200, cleared with a note.")
// and rule 2's "Quiet for 23 days" both name a touch older than any range
// the API serves (14d is the widest range in Range) -- so, unlike every
// other value in this module, there is no field in Canary/Visitor to
// compute it from. This is gen.py's QUIET_DAY story (2026-09-05, a touch
// on 2026-08-13), kept as one named constant rather than copied into both
// rules, and overridable via QuietStory for whenever the API grows a
// "last touch outside the window" field.
export interface QuietStory {
  lastTouchAt: string
  lastTouchDateLabel: string
  lastTouchPrefix: string
  lastTouchIp: string
  lastTouchSuffix: string
}

export const DEFAULT_QUIET_STORY: QuietStory = {
  lastTouchAt: '2026-08-13T00:00:00Z',
  lastTouchDateLabel: 'Thu 13 Aug',
  lastTouchPrefix: 'one touch on canary-guest :23 from ',
  lastTouchIp: '198.51.100.200',
  lastTouchSuffix: ', cleared with a note.',
}

/** Days between the story's last touch and `now` -- "23" for both the
 * quiet and silent fixtures (2026-08-13 -> 2026-09-05). */
export function computeQuietDays(now: string, story: QuietStory = DEFAULT_QUIET_STORY): number {
  return calendarDaysBetween(story.lastTouchAt, now)
}
