// A canary tile's status line (issue #38 / gen.py tiles()):
//   ok, no hits:      "● 9 s · every minute · quiet 23 d"
//   ok, with hits:    "● 9 s · ✱ swept 21:55" then, on its own line, the
//                      next visitor kind ("from inside 19:11", "one touch
//                      yesterday") -- except a repeat, which stays on the
//                      same line ("✱ swept 22:01 · repeat :445"), per the
//                      issue: "a deliberate line break before a second
//                      visitor" (repeat is the one kind that isn't a
//                      second visitor -- it's the same one, still knocking).
//   silent:           "○ silent 6 m 12 s · last heard 21:58:19"
// Reads TraceCanary (fetchTrace), not Canary (fetchCanaries) -- the hit
// times and kinds this needs only exist at that granularity.
import type { VisitorKind } from '../types'
import { durationExact } from './duration'
import { formatClock, formatClockShort, relativeDayLabel } from './time'
import { portForService } from './ports'
import { DEFAULT_QUIET_STORY, computeQuietDays, type QuietStory } from './quietStory'
import type { Segment } from './types'

export interface TileHit {
  at: string
  kind: VisitorKind
  service: string
}

export interface TileCanaryInput {
  status: 'ok' | 'silent'
  last_heartbeat_at: string | null
  silent_for_s?: number
  ports: string
  hits: TileHit[]
}

export interface TileStatusResult {
  /** One or two lines; a second line is a line break, never inline. */
  lines: Segment[][]
}

function beatAgoSeconds(lastHeartbeatAt: string | null, now: string): number {
  if (!lastHeartbeatAt) return 0
  return Math.max(0, Math.round((Date.parse(now) - Date.parse(lastHeartbeatAt)) / 1000))
}

export function computeTileStatus(
  canary: TileCanaryInput,
  now: string,
  story: QuietStory = DEFAULT_QUIET_STORY,
): TileStatusResult {
  if (canary.status === 'silent') {
    return {
      lines: [
        [
          {
            text: `○ silent ${durationExact(canary.silent_for_s ?? 0)} · last heard ${formatClock(canary.last_heartbeat_at ?? now)}`,
            cls: 'off',
          },
        ],
      ],
    }
  }

  const beat = beatAgoSeconds(canary.last_heartbeat_at, now)
  const hits = canary.hits ?? []

  if (hits.length === 0) {
    const days = computeQuietDays(now, story)
    return {
      lines: [[{ text: `● ${beat} s`, cls: 'ok' }, { text: ` · every minute · quiet ${days} d` }]],
    }
  }

  const primary: Segment[] = [{ text: `● ${beat} s`, cls: 'ok' }]
  const sweeps = hits.filter((h) => h.kind === 'sweep')
  if (sweeps.length > 0) {
    const earliest = sweeps.reduce((a, b) => (Date.parse(b.at) < Date.parse(a.at) ? b : a))
    primary.push({ text: ' · ' }, { text: `✱ swept ${formatClockShort(earliest.at)}`, cls: 'al' })
  }

  const others = hits.filter((h) => h.kind !== 'sweep')
  if (others.length === 0) return { lines: [primary] }

  const rep = others.reduce((a, b) => (Date.parse(b.at) > Date.parse(a.at) ? b : a))
  if (rep.kind === 'repeat') {
    const port = portForService(canary.ports, rep.service)
    return {
      lines: [[...primary, { text: ' · ' }, { text: `repeat${port ? ` :${port}` : ''}`, cls: 'rp' }]],
    }
  }
  const secondary: Segment[] =
    rep.kind === 'inside'
      ? [{ text: `from inside ${formatClockShort(rep.at)}` }]
      : [{ text: `one touch ${relativeDayLabel(rep.at, now)}` }]
  return { lines: [primary, secondary] }
}
