// The top-right status pill (issue #38): "● LIVE · 4 canaries", "⚑ 1",
// "◎ 4 visitors"; silent: "○ 3 of 4 phoning home · canary-iot silent 6 m".
// issue #45 folds throttled/not-delivering/token-conflict ('critical')
// and rotation-stalled ('degraded') into the same precedence slot silent
// already held -- checked ahead of 'live', by the ranked worst active
// state across the fleet, mirroring internal/store/health.go's
// healthStateRank (duplicated here rather than shared: this is a display
// ordering over an API response, not database logic).
import type { Canary, CanaryStatus, Range, Visitor } from '../types'
import { durationCoarse } from './duration'

export type StatusInfo =
  | { kind: 'quiet'; okCount: number; total: number; visitorCount: number; range: Range }
  | {
      kind: 'silent'
      okCount: number
      total: number
      visitorCount: number
      range: Range
      silentName: string
      silentFor: string
    }
  | {
      kind: 'critical' | 'degraded'
      okCount: number
      total: number
      visitorCount: number
      range: Range
      canaryName: string
      label: string
    }
  | { kind: 'live'; total: number; visitorCount: number; flagCount: number }

const RANK: Record<CanaryStatus, number> = {
  token_conflict: 0,
  // ADR-0012 Part B (#130): ranked with token_conflict, same severity.
  credential_conflict: 0,
  silent: 1,
  not_delivering: 2,
  // Issue #45, owner-ratified 2026-09-25: ranked straight after
  // not_delivering, ahead of self_test_failed.
  hits_merged: 3,
  self_test_failed: 4,
  // ADR-0012 decision 10 (#116): ranked between self_test_failed and
  // throttled, exactly where the ADR puts it.
  db_stale: 5,
  throttled: 6,
  rotation_stalled: 7,
  // ADR-0012 Part B: ranked with rotation_stalled, its certificate twin.
  renewal_stalled: 7,
  pending: 8,
  ok: 9,
}

function worstOf(canaries: Canary[]): Canary | null {
  let worst: Canary | null = null
  for (const c of canaries) {
    if (c.status === 'ok') continue
    if (!worst || RANK[c.status] < RANK[worst.status]) worst = c
  }
  return worst
}

/** Short pill-length label, not #38's hero-sentence prose -- reuses the
 * issue's own wording ("look at the box now") rather than inventing a
 * new voice for this compact slot. */
function label(c: Canary): string {
  switch (c.status) {
    case 'token_conflict':
      return `${c.name} token conflict ${durationCoarse(c.token_conflict_for_s ?? 0)} — look at the box now`
    case 'credential_conflict':
      return `${c.name} credential conflict — revoke the node`
    case 'not_delivering':
      return `${c.name} not delivering`
    case 'hits_merged':
      return `${c.name} hits merged`
    case 'self_test_failed': {
      const services = c.self_test_failed_services ?? []
      return `${c.name} self-test failed${services.length > 0 ? `: ${services.join(', ')}` : ''}`
    }
    // ADR-0012 decision 10 (#116): no *_for_s field is sent for this
    // state -- the hours are computed from db_refresh.failing_since,
    // which this compact pill does not have `now` to measure against
    // (computeStatus takes no `now`, unlike computeSentence/tileStatus).
    // The pill names the canary and the state; the hours are on the
    // tile and the canary page, which both take `now`.
    case 'db_stale':
      return `${c.name} vulnerability database stale`
    case 'throttled':
      return `${c.name} throttled ${durationCoarse(c.throttled_for_s ?? 0)}`
    case 'rotation_stalled':
      return `${c.name} rotation stalled ${durationCoarse(c.rotation_stalled_for_s ?? 0)}`
    case 'renewal_stalled':
      return `${c.name} renewal stalled ${durationCoarse(c.renewal_stalled_for_s ?? 0)}`
    default:
      return c.name
  }
}

export function computeStatus(canaries: Canary[], visitors: Visitor[], range: Range): StatusInfo {
  // "Phoning home" is heartbeat receipt, not overall health: a
  // throttled or not-delivering canary is still beating, so it counts
  // here exactly as a plain 'ok' one does -- only 'silent' doesn't.
  const okCount = canaries.filter((c) => c.status !== 'silent').length
  const total = canaries.length
  const visitorCount = visitors.length
  const worst = worstOf(canaries)

  if (worst?.status === 'silent') {
    return {
      kind: 'silent',
      okCount,
      total,
      visitorCount,
      range,
      silentName: worst.name,
      silentFor: durationCoarse(worst.silent_for_s ?? 0),
    }
  }
  if (
    worst?.status === 'token_conflict' ||
    worst?.status === 'credential_conflict' ||
    worst?.status === 'not_delivering' ||
    worst?.status === 'hits_merged' ||
    worst?.status === 'self_test_failed' ||
    worst?.status === 'db_stale' ||
    worst?.status === 'throttled'
  ) {
    return { kind: 'critical', okCount, total, visitorCount, range, canaryName: worst.name, label: label(worst) }
  }
  if (worst?.status === 'rotation_stalled' || worst?.status === 'renewal_stalled') {
    return { kind: 'degraded', okCount, total, visitorCount, range, canaryName: worst.name, label: label(worst) }
  }
  if (visitorCount > 0) {
    const flagCount = visitors.filter((v) => v.kind === 'sweep' && v.still_arriving).length
    return { kind: 'live', total, visitorCount, flagCount }
  }
  return { kind: 'quiet', okCount, total, visitorCount, range }
}
