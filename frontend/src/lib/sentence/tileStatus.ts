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
import type { CanaryStatus, LastHit, VisitorKind } from '../types'
import { durationExact } from './duration'
import { formatClock, formatClockShort, relativeDayLabel } from './time'
import { portForService } from './ports'
import { buildQuietStory, computeQuietDays } from './quietStory'
import type { Segment } from './types'

export interface TileHit {
  at: string
  kind: VisitorKind
  service: string
}

export interface TileCanaryInput {
  status: CanaryStatus
  last_heartbeat_at: string | null
  silent_for_s?: number
  ports: string
  hits: TileHit[]
  // issue #45: the states silent doesn't cover, each carried
  // independently of which one `status` reports as the tile's headline
  // (see health.go's applyHealthState: "one state on the tile, the
  // worst; the rest in its detail").
  not_delivering?: boolean
  throttled_for_s?: number
  rotation_stalled?: boolean
  rotation_stalled_for_s?: number
  rotation_stalled_escalated?: boolean
  token_conflict_for_s?: number
  // ADR-0012 Part B (issue #130): renewal_stalled is rotation_stalled's
  // certificate twin, credential_conflict_for_s is token_conflict_for_s's
  // -- same independent-of-`status` carrying.
  renewal_stalled?: boolean
  renewal_stalled_for_s?: number
  renewal_stalled_escalated?: boolean
  credential_conflict_for_s?: number
  // issue #46: the most recently completed self-test round, carried the
  // same independent way -- present whether or not it is what made
  // `status` self_test_failed, since a passing run still earns its own
  // line on an otherwise-healthy tile (note 22577).
  last_self_test_at?: string | null
  last_self_test_passed?: boolean
  self_test_failed_services?: string[]
}

export interface TileStatusResult {
  /** One to three lines; each further line is a line break, never inline. */
  lines: Segment[][]
}

function beatAgoSeconds(lastHeartbeatAt: string | null, now: string): number {
  if (!lastHeartbeatAt) return 0
  return Math.max(0, Math.round((Date.parse(now) - Date.parse(lastHeartbeatAt)) / 1000))
}

/** "passed" or "failed: vnc, ntp" (no colon-list when the list is empty)
 * -- the self-test line's verdict clause, shared by the failed tile's own
 * line and the honest-render appendix below. */
function selfTestVerdict(canary: TileCanaryInput): string {
  if (canary.last_self_test_passed === false) {
    const services = canary.self_test_failed_services ?? []
    return services.length > 0 ? `failed: ${services.join(', ')}` : 'failed'
  }
  return 'passed'
}

/** Issue #46, note 22577: on an otherwise-healthy tile, one more line
 * naming the last completed self-test -- "self-test 04:00 · passed".
 * Only on the three healthy returns computeTileStatus names below (not
 * silent, not any other-state line -- those already carry their own
 * self-test line, or none applies). null when no run has ever
 * completed, so a freshly provisioned canary's tile stays as it was. */
function selfTestAppendix(canary: TileCanaryInput): Segment[] | null {
  if (!canary.last_self_test_at) return null
  return [{ text: `self-test ${formatClockShort(canary.last_self_test_at)} · ${selfTestVerdict(canary)}` }]
}

function withSelfTest(lines: Segment[][], canary: TileCanaryInput): TileStatusResult {
  const appendix = selfTestAppendix(canary)
  return { lines: appendix ? [...lines, appendix] : lines }
}

/** issue #45's critical/degraded states other than silent, one line each
 * in the "○ silent 6 m · last heard HH:MM:SS" pattern that state already
 * established: icon, short label, duration where one applies, then the
 * operator's next step -- reusing the issue's own wording rather than
 * inventing new copy for a voice #38's hero sentence would otherwise
 * need to set (see rules.ts, not touched by this slice).
 * cls 'al' is the existing critical/alarm colour (Tiles.svelte); 'wn' is
 * new here for the degraded tier, reusing the existing --repeat colour
 * token rather than picking a new one. */
function otherStateLine(canary: TileCanaryInput): Segment[] | null {
  switch (canary.status as CanaryStatus) {
    case 'token_conflict':
      // ADR-0012 Part B widens this to also mean a superseded
      // certificate still in use, not tokens alone.
      return [
        {
          text: `⚠ token conflict ${durationExact(canary.token_conflict_for_s ?? 0)} · a revoked credential was reused — look at the box now`,
          cls: 'al',
        },
      ]
    case 'credential_conflict':
      // ADR-0012 Part B (#130): the same live credential seen from two
      // places at once, ranked with token_conflict (same 'al' colour).
      return [
        {
          text: `⚠ credential conflict ${durationExact(canary.credential_conflict_for_s ?? 0)} · in use from two places at once — revoke the node`,
          cls: 'al',
        },
      ]
    case 'not_delivering':
      return [{ text: `⚠ not delivering · the agent can't read its log`, cls: 'al' }]
    case 'self_test_failed':
      // Issue #46 (health.go's StateTestFailed, note 22577's tile line):
      // birdcage's own daily self-test found a service that never
      // answered its probe. The list names exactly the targets that
      // never matched (SelfTestFailedServices), never every service the
      // canary runs -- an empty list still reads as a whole clause,
      // never a dangling colon.
      return [
        {
          text: `⚠ self-test ${formatClockShort(canary.last_self_test_at ?? '')} · ${selfTestVerdict(canary)} — check those services on the box`,
          cls: 'al',
        },
      ]
    case 'throttled':
      return [
        {
          text: `⚠ throttled ${durationExact(canary.throttled_for_s ?? 0)} · rate limit crossed — check for a flood or a broken agent`,
          cls: 'al',
        },
      ]
    case 'pending':
      // Issue #47 steps 7-9: provisioned but not yet proven end to end
      // -- #45's own third category, not a fault. No duration field: a
      // pending canary has no "since" the API carries (registered_at is
      // null by definition), unlike every other state's own *_for_s.
      return [{ text: `◌ pending · waiting on its first self-test to confirm the chain works`, cls: 'wn' }]
    case 'rotation_stalled': {
      // Not escalated is signal A only (a freshly issued token unused for
      // 15 min to 24 h). Escalated is either signal A past 24 h or signal
      // B (no completed rotation in ~25 h), and in both of those no
      // rotation has actually completed -- see rotationSignal in
      // internal/store/health.go. Each branch is a whole clause: an
      // interpolated tail read as "hasn't rotated in check the agent".
      const what = canary.rotation_stalled_escalated
        ? 'no rotation completed in over a day'
        : "a fresh token hasn't been picked up"
      return [
        {
          text: `⏳ rotation stalled ${durationExact(canary.rotation_stalled_for_s ?? 0)} · ${what} — check the agent`,
          cls: 'wn',
        },
      ]
    }
    case 'renewal_stalled': {
      // ADR-0012 Part B (#130): rotation_stalled's certificate twin --
      // the agent renews its own certificate from half-life (ADR-0012
      // B2) rather than birdcage issuing one, so the not-escalated
      // clause names that instead of "a fresh token".
      const what = canary.renewal_stalled_escalated
        ? 'no renewal completed in over a day'
        : "past its renewal point, not yet renewed"
      return [
        {
          text: `⏳ renewal stalled ${durationExact(canary.renewal_stalled_for_s ?? 0)} · ${what} — check the agent can reach ingest`,
          cls: 'wn',
        },
      ]
    }
    default:
      return null
  }
}

export function computeTileStatus(
  canary: TileCanaryInput,
  now: string,
  lastHit: LastHit | null = null,
): TileStatusResult {
  const other = otherStateLine(canary)
  if (other) {
    return { lines: [other] }
  }

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
    const days = computeQuietDays(now, buildQuietStory(lastHit))
    return withSelfTest([[{ text: `● ${beat} s`, cls: 'ok' }, { text: ` · every minute · quiet ${days} d` }]], canary)
  }

  const primary: Segment[] = [{ text: `● ${beat} s`, cls: 'ok' }]
  const sweeps = hits.filter((h) => h.kind === 'sweep')
  if (sweeps.length > 0) {
    const earliest = sweeps.reduce((a, b) => (Date.parse(b.at) < Date.parse(a.at) ? b : a))
    primary.push({ text: ' · ' }, { text: `✱ swept ${formatClockShort(earliest.at)}`, cls: 'al' })
  }

  const others = hits.filter((h) => h.kind !== 'sweep')
  if (others.length === 0) return withSelfTest([primary], canary)

  const rep = others.reduce((a, b) => (Date.parse(b.at) > Date.parse(a.at) ? b : a))
  if (rep.kind === 'repeat') {
    const port = portForService(canary.ports, rep.service)
    return withSelfTest(
      [[...primary, { text: ' · ' }, { text: `repeat${port ? ` :${port}` : ''}`, cls: 'rp' }]],
      canary,
    )
  }
  const secondary: Segment[] =
    rep.kind === 'inside'
      ? [{ text: `from inside ${formatClockShort(rep.at)}` }]
      : [{ text: `one touch ${relativeDayLabel(rep.at, now)}` }]
  return withSelfTest([primary, secondary], canary)
}
