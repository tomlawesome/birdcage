import { wordOrNumber, plural } from './words'

/** "6 m 12 s" / "9 s" -- the tile's and the dropped-row's exact duration
 * (gen.py: "silent 6 m 12 s", "○ silent 6 m 12 s · last heard 21:58:19").
 * The ladder climbs for issue #45: token conflict's window reaches a
 * day and an escalated stalled rotation is past one by definition, so
 * hour and day scales exist now ("1500 m 0 s" is the wrong voice, as
 * agoWords already notes). Always the two largest units that apply --
 * the same shape "6 m 12 s" set -- and "d" is the unit the ok tile's
 * "quiet 23 d" already speaks. Under an hour nothing changes, so #38's
 * hand-tuned silent copy renders byte-identically. */
export function durationExact(totalSeconds: number): string {
  const d = Math.floor(totalSeconds / 86400)
  const h = Math.floor((totalSeconds % 86400) / 3600)
  if (d > 0) return `${d} d ${h} h`
  const m = Math.floor((totalSeconds % 3600) / 60)
  if (h > 0) return `${h} h ${m} m`
  const s = Math.floor(totalSeconds % 60)
  return m > 0 ? `${m} m ${s} s` : `${s} s`
}

/** "6 m" -- the status pill's coarser duration (renamed from
 * durationMinutesOnly when the ladder outgrew minutes) (gen.py STATUS.silent:
 * "canary-iot silent 6 m", no seconds). One unit, the largest that
 * applies, climbing to "2 h" / "1 d" for the #45 states whose windows
 * pass an hour (the pill said "token conflict 1140 m" otherwise);
 * under an hour it is unchanged. */
export function durationCoarse(totalSeconds: number): string {
  const d = Math.floor(totalSeconds / 86400)
  if (d > 0) return `${d} d`
  const h = Math.floor(totalSeconds / 3600)
  if (h > 0) return `${h} h`
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
