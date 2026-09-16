import { wordOrNumber, plural } from './words'

/** "6 m 12 s" / "9 s" -- the tile's and the dropped-row's exact duration
 * (gen.py: "silent 6 m 12 s", "○ silent 6 m 12 s · last heard 21:58:19"). */
export function durationExact(totalSeconds: number): string {
  const m = Math.floor(totalSeconds / 60)
  const s = Math.floor(totalSeconds % 60)
  return m > 0 ? `${m} m ${s} s` : `${s} s`
}

/** "6 m" -- the status pill's coarser duration (gen.py STATUS.silent:
 * "canary-iot silent 6 m", no seconds). */
export function durationMinutesOnly(totalSeconds: number): string {
  return `${Math.floor(totalSeconds / 60)} m`
}

/** "six minutes ago" / "three seconds ago" -- prose, so numbers under ten
 * are spelled out (issue #38). Hours ("19 hours ago") added for issue
 * #45: the token-conflict and rotation windows reach a day, where
 * "1140 minutes ago" would be the wrong voice; silent never got there. */
export function agoWords(totalSeconds: number): string {
  const h = Math.floor(totalSeconds / 3600)
  if (h > 0) return `${wordOrNumber(h)} ${plural(h, 'hour')} ago`
  const m = Math.floor(totalSeconds / 60)
  if (m > 0) return `${wordOrNumber(m)} ${plural(m, 'minute')} ago`
  const s = Math.floor(totalSeconds)
  return `${wordOrNumber(s)} ${plural(s, 'second')} ago`
}
