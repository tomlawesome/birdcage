// issue #45: the tile-level rendering of the four states silent didn't
// already cover. The silent/ok branches themselves are unchanged and
// stay covered by the existing pixel-gate fixtures (quiet/silent/night);
// these are new branches with no fixture yet, so they need their own
// direct coverage.
import { describe, expect, it } from 'vitest'
import { computeTileStatus, type TileCanaryInput } from './tileStatus'
import { plainText } from './types'

const base: TileCanaryInput = {
  status: 'ok',
  last_heartbeat_at: '2026-01-01T00:00:00Z',
  ports: 'ssh 22',
  hits: [],
}

describe('computeTileStatus: issue #45 states', () => {
  it('token_conflict: names the state and says to look at the box now', () => {
    const result = computeTileStatus({ ...base, status: 'token_conflict', token_conflict_for_s: 125 }, '2026-01-01T00:02:05Z')
    expect(result.lines).toHaveLength(1)
    const text = plainText(result.lines[0])
    expect(text).toContain('token conflict')
    expect(text).toContain('look at the box now')
    expect(result.lines[0][0].cls).toBe('al')
  })

  it('not_delivering: names the log-read failure', () => {
    const result = computeTileStatus({ ...base, status: 'not_delivering' }, '2026-01-01T00:00:00Z')
    const text = plainText(result.lines[0])
    expect(text).toContain('not delivering')
    expect(text).toContain("can't read its log")
    expect(result.lines[0][0].cls).toBe('al')
  })

  it('throttled: shows the duration and the operator hint', () => {
    const result = computeTileStatus({ ...base, status: 'throttled', throttled_for_s: 90 }, '2026-01-01T00:01:30Z')
    const text = plainText(result.lines[0])
    expect(text).toContain('throttled')
    expect(text).toContain('flood or a broken agent')
    expect(result.lines[0][0].cls).toBe('al')
  })

  it('rotation_stalled: not yet escalated reads differently from escalated', () => {
    const fresh = computeTileStatus(
      { ...base, status: 'rotation_stalled', rotation_stalled_for_s: 900, rotation_stalled_escalated: false },
      '2026-01-01T00:15:00Z',
    )
    const stale = computeTileStatus(
      { ...base, status: 'rotation_stalled', rotation_stalled_for_s: 90000, rotation_stalled_escalated: true },
      '2026-01-02T01:00:00Z',
    )
    expect(plainText(fresh.lines[0])).toContain('rotation stalled')
    expect(plainText(fresh.lines[0])).not.toContain('over a day')
    expect(plainText(stale.lines[0])).toContain('over a day')
    // Each branch must be a whole clause. An earlier version interpolated
    // only a tail and rendered "hasn't rotated in check the agent"; a
    // contains() check on either half passed straight over it, so assert
    // the clause entire. Asserted after the "· " so the duration's own
    // formatting is not pinned here -- duration.test.ts owns that.
    expect(plainText(fresh.lines[0]).split('· ')[1]).toBe(
      "a fresh token hasn't been picked up — check the agent",
    )
    expect(plainText(stale.lines[0]).split('· ')[1]).toBe(
      'no rotation completed in over a day — check the agent',
    )
  })

  it('silent still takes the original branch, unchanged', () => {
    const result = computeTileStatus({ ...base, status: 'silent', silent_for_s: 372 }, '2026-01-01T00:06:12Z')
    expect(plainText(result.lines[0])).toContain('silent')
    expect(result.lines[0][0].cls).toBe('off')
  })

  // Issue #47 steps 7-9.
  it('pending: names the state and its own detail line, not a fault colour', () => {
    const result = computeTileStatus({ ...base, status: 'pending' }, '2026-01-01T00:00:00Z')
    expect(result.lines).toHaveLength(1)
    const text = plainText(result.lines[0])
    expect(text).toContain('pending')
    expect(text).toContain('self-test')
    // The degraded-tier colour ('wn'), never the critical-tier alarm
    // colour ('al') -- pending is #45's own third category, not a fault.
    expect(result.lines[0][0].cls).toBe('wn')
  })
})

// Issue #46: the tile line note 22577 asks for -- one line naming the
// failed self-test on a self_test_failed tile, and one more appended to
// an otherwise-healthy tile's own line reporting the last self-test that
// did complete.
describe('computeTileStatus: issue #46 self-test line', () => {
  it('self_test_failed: names the failed services and says to check the box', () => {
    const result = computeTileStatus(
      {
        ...base,
        status: 'self_test_failed',
        last_self_test_at: '2026-01-01T04:00:00Z',
        last_self_test_passed: false,
        self_test_failed_services: ['vnc', 'ntp'],
      },
      '2026-01-01T04:05:00Z',
    )
    expect(result.lines).toHaveLength(1)
    const text = plainText(result.lines[0])
    expect(text).toBe('⚠ self-test 04:00 · failed: vnc, ntp — check those services on the box')
    expect(result.lines[0][0].cls).toBe('al')
  })

  it('self_test_failed: an empty service list still reads as a whole clause, no dangling colon', () => {
    const result = computeTileStatus(
      {
        ...base,
        status: 'self_test_failed',
        last_self_test_at: '2026-01-01T04:00:00Z',
        last_self_test_passed: false,
        self_test_failed_services: [],
      },
      '2026-01-01T04:05:00Z',
    )
    expect(plainText(result.lines[0])).toBe('⚠ self-test 04:00 · failed — check those services on the box')
  })

  it('a passing self-test appends a second line on the no-hits branch', () => {
    const result = computeTileStatus(
      {
        ...base,
        status: 'ok',
        last_self_test_at: '2026-01-01T04:00:00Z',
        last_self_test_passed: true,
      },
      '2026-01-01T04:05:09Z',
    )
    expect(result.lines).toHaveLength(2)
    expect(plainText(result.lines[1])).toBe('self-test 04:00 · passed')
    // No cls on the appended line -- it is not an alarm, just a fact.
    expect(result.lines[1][0].cls).toBeUndefined()
  })

  it('no self-test line at all when last_self_test_at is null', () => {
    const result = computeTileStatus(
      { ...base, status: 'ok', last_self_test_at: null },
      '2026-01-01T00:00:09Z',
    )
    expect(result.lines).toHaveLength(1)
  })

  it('a silent tile never gets the appended self-test line', () => {
    const result = computeTileStatus(
      {
        ...base,
        status: 'silent',
        silent_for_s: 372,
        last_self_test_at: '2026-01-01T04:00:00Z',
        last_self_test_passed: true,
      },
      '2026-01-01T00:06:12Z',
    )
    expect(result.lines).toHaveLength(1)
  })

  it('an honest render: status still ok but last_self_test_passed is false', () => {
    const result = computeTileStatus(
      {
        ...base,
        status: 'ok',
        last_self_test_at: '2026-01-01T04:00:00Z',
        last_self_test_passed: false,
        self_test_failed_services: ['ntp'],
      },
      '2026-01-01T04:05:09Z',
    )
    expect(plainText(result.lines[1])).toBe('self-test 04:00 · failed: ntp')
  })
})
