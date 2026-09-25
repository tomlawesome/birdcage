import { describe, expect, it } from 'vitest'
import quietFixture from '../../dev/fixtures/quiet.json'
import silentFixture from '../../dev/fixtures/silent.json'
import nightFixture from '../../dev/fixtures/night.json'
import { computeStatus } from './status'
import type { Canary, Visitor } from '../types'

const quiet = quietFixture as { canaries: { canaries: Canary[] }; visitors: { visitors: Visitor[] } }
const silent = silentFixture as typeof quiet
const night = nightFixture as typeof quiet

describe('the status pill (issue #38)', () => {
  it('quiet fixture: QUIET · 4 of 4 phoning home, 0 visitors', () => {
    const s = computeStatus(quiet.canaries.canaries, quiet.visitors.visitors, '14d')
    expect(s).toEqual({ kind: 'quiet', okCount: 4, total: 4, visitorCount: 0, range: '14d' })
  })

  it('silent fixture: 3 of 4 phoning home · canary-iot silent 6 m', () => {
    const s = computeStatus(silent.canaries.canaries, silent.visitors.visitors, '14d')
    expect(s).toEqual({
      kind: 'silent',
      okCount: 3,
      total: 4,
      visitorCount: 0,
      range: '14d',
      silentName: 'canary-iot',
      silentFor: '6 m',
    })
  })

  it('night fixture: LIVE · 4 canaries, flagged 1, 4 visitors', () => {
    const s = computeStatus(night.canaries.canaries, night.visitors.visitors, '14d')
    expect(s).toEqual({ kind: 'live', total: 4, visitorCount: 4, flagCount: 1 })
  })
})

// issue #45: throttled/not-delivering/token-conflict ('critical') and
// rotation-stalled ('degraded') slot into the same precedence position
// silent already held. These build canaries directly (no fixture covers
// the new states yet) to isolate the ranking from any fixture-specific
// detail.
function canary(id: string, status: Canary['status'], extra: Partial<Canary> = {}): Canary {
  return {
    id,
    name: id,
    lane: 'lan',
    ports: '',
    status,
    last_heartbeat_at: '2026-01-01T00:00:00Z',
    hits: 0,
    ...extra,
  }
}

describe('the status pill: issue #45 ranking', () => {
  it('a lone throttled canary reads as critical, "phoning home" still counts it', () => {
    const canaries = [canary('a', 'throttled', { throttled_for_s: 60 }), canary('b', 'ok')]
    const s = computeStatus(canaries, [], '14d')
    expect(s.kind).toBe('critical')
    if (s.kind === 'critical' || s.kind === 'degraded') {
      expect(s.okCount).toBe(2) // both are beating; only 'silent' isn't
      expect(s.canaryName).toBe('a')
      expect(s.label).toContain('throttled')
    }
  })

  it('a lone rotation-stalled canary reads as degraded', () => {
    const canaries = [canary('a', 'rotation_stalled', { rotation_stalled_for_s: 1000 })]
    const s = computeStatus(canaries, [], '14d')
    expect(s.kind).toBe('degraded')
  })

  it('token conflict outranks silent', () => {
    const canaries = [canary('a', 'silent', { silent_for_s: 60 }), canary('b', 'token_conflict', { token_conflict_for_s: 30 })]
    const s = computeStatus(canaries, [], '14d')
    expect(s.kind).toBe('critical')
    if (s.kind === 'critical') expect(s.canaryName).toBe('b')
  })

  it('silent outranks not_delivering and rotation_stalled', () => {
    const canaries = [
      canary('a', 'not_delivering'),
      canary('b', 'silent', { silent_for_s: 60 }),
      canary('c', 'rotation_stalled', { rotation_stalled_for_s: 1000 }),
    ]
    const s = computeStatus(canaries, [], '14d')
    expect(s.kind).toBe('silent')
    if (s.kind === 'silent') expect(s.silentName).toBe('b')
  })

  it('not_delivering outranks throttled', () => {
    const canaries = [canary('a', 'throttled', { throttled_for_s: 60 }), canary('b', 'not_delivering')]
    const s = computeStatus(canaries, [], '14d')
    expect(s.kind).toBe('critical')
    if (s.kind === 'critical') expect(s.canaryName).toBe('b')
  })

  // Issue #47 steps 7-9: pending is #45's own third category, not a
  // fault -- the pill has no dedicated rendering for it (unlike
  // critical/degraded), so a lone pending canary falls through to the
  // ordinary quiet/live read, same as a fleet with nothing wrong at all.
  it('a lone pending canary does not read as critical or degraded', () => {
    const canaries = [canary('a', 'pending')]
    const s = computeStatus(canaries, [], '14d')
    expect(s.kind).toBe('quiet')
  })

  it('rotation_stalled outranks pending', () => {
    const canaries = [canary('a', 'pending'), canary('b', 'rotation_stalled', { rotation_stalled_for_s: 1000 })]
    const s = computeStatus(canaries, [], '14d')
    expect(s.kind).toBe('degraded')
    if (s.kind === 'degraded') expect(s.canaryName).toBe('b')
  })

  // Issue #46: self_test_failed joins the critical kind, between
  // not_delivering and throttled in health.go's own order.
  it('a lone self_test_failed canary reads as critical, with the failed services in the label', () => {
    const canaries = [canary('a', 'self_test_failed', { self_test_failed_services: ['vnc', 'ntp'] }), canary('b', 'ok')]
    const s = computeStatus(canaries, [], '14d')
    expect(s.kind).toBe('critical')
    if (s.kind === 'critical') {
      expect(s.canaryName).toBe('a')
      expect(s.label).toBe('a self-test failed: vnc, ntp')
    }
  })

  it('self_test_failed with no named services still reads as a whole clause', () => {
    const canaries = [canary('a', 'self_test_failed', { self_test_failed_services: [] })]
    const s = computeStatus(canaries, [], '14d')
    if (s.kind === 'critical') expect(s.label).toBe('a self-test failed')
  })

  it('not_delivering outranks self_test_failed', () => {
    const canaries = [canary('a', 'self_test_failed'), canary('b', 'not_delivering')]
    const s = computeStatus(canaries, [], '14d')
    expect(s.kind).toBe('critical')
    if (s.kind === 'critical') expect(s.canaryName).toBe('b')
  })

  it('self_test_failed outranks throttled', () => {
    const canaries = [canary('a', 'throttled', { throttled_for_s: 60 }), canary('b', 'self_test_failed')]
    const s = computeStatus(canaries, [], '14d')
    expect(s.kind).toBe('critical')
    if (s.kind === 'critical') expect(s.canaryName).toBe('b')
  })

  // ADR-0012 Part B (issue #130): credential_conflict ties token_conflict
  // (same red severity); renewal_stalled ties rotation_stalled (its
  // certificate twin).
  it('credential_conflict reads as critical, ranked with token_conflict', () => {
    const canaries = [
      canary('a', 'silent', { silent_for_s: 60 }),
      canary('b', 'credential_conflict', { credential_conflict: { addresses: ['10.0.0.1', '10.0.0.2'] } }),
    ]
    const s = computeStatus(canaries, [], '14d')
    expect(s.kind).toBe('critical')
    if (s.kind === 'critical') {
      expect(s.canaryName).toBe('b')
      expect(s.label).toBe('b credential conflict — revoke the node')
    }
  })

  it('renewal_stalled reads as degraded, ranked with rotation_stalled', () => {
    const canaries = [canary('a', 'pending'), canary('b', 'renewal_stalled', { renewal_stalled_for_s: 1800 })]
    const s = computeStatus(canaries, [], '14d')
    expect(s.kind).toBe('degraded')
    if (s.kind === 'degraded') {
      expect(s.canaryName).toBe('b')
      expect(s.label).toBe('b renewal stalled 30 m')
    }
  })
})

// Issue #45, owner-ratified 2026-09-25: hits_merged joins the critical
// kind, ranked straight after not_delivering, ahead of self_test_failed.
describe('the status pill: issue #45 hits_merged', () => {
  it('a lone hits_merged canary reads as critical, naming the canary', () => {
    const canaries = [canary('a', 'hits_merged', { event_id_collisions: 3 }), canary('b', 'ok')]
    const s = computeStatus(canaries, [], '14d')
    expect(s.kind).toBe('critical')
    if (s.kind === 'critical') {
      expect(s.canaryName).toBe('a')
      expect(s.label).toBe('a hits merged')
    }
  })

  it('not_delivering outranks hits_merged, which outranks self_test_failed', () => {
    const canaries = [
      canary('a', 'self_test_failed'),
      canary('b', 'hits_merged', { event_id_collisions: 1 }),
      canary('c', 'not_delivering'),
    ]
    const s = computeStatus(canaries, [], '14d')
    expect(s.kind).toBe('critical')
    if (s.kind === 'critical') expect(s.canaryName).toBe('c')

    const s2 = computeStatus([canaries[0], canaries[1]], [], '14d')
    if (s2.kind === 'critical') expect(s2.canaryName).toBe('b')
  })
})

// ADR-0012 decision 10 (issue #116): db_stale joins the critical kind,
// ranked between self_test_failed and throttled.
describe('the status pill: ADR-0012 db_stale', () => {
  it('a lone db_stale canary reads as critical, naming the canary', () => {
    const canaries = [canary('a', 'db_stale', { db_refresh: { failing_since: '2026-01-01T00:00:00Z', last_error: 'timeout' } }), canary('b', 'ok')]
    const s = computeStatus(canaries, [], '14d')
    expect(s.kind).toBe('critical')
    if (s.kind === 'critical') {
      expect(s.canaryName).toBe('a')
      expect(s.label).toContain('vulnerability database stale')
    }
  })

  it('self_test_failed outranks db_stale, which outranks throttled', () => {
    const canaries = [
      canary('a', 'throttled', { throttled_for_s: 60 }),
      canary('b', 'db_stale'),
      canary('c', 'self_test_failed'),
    ]
    const s = computeStatus(canaries, [], '14d')
    expect(s.kind).toBe('critical')
    if (s.kind === 'critical') expect(s.canaryName).toBe('c')

    const s2 = computeStatus([canaries[0], canaries[1]], [], '14d')
    if (s2.kind === 'critical') expect(s2.canaryName).toBe('b')
  })
})
