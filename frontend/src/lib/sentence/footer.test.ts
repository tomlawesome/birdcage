import { describe, expect, it } from 'vitest'
import quietFixture from '../../dev/fixtures/quiet.json'
import silentFixture from '../../dev/fixtures/silent.json'
import nightFixture from '../../dev/fixtures/night.json'
import alertsFixture from '../../dev/fixtures/alerts.json'
import { computeFooter } from './footer'
import { plainText } from './types'
import type { Canary, LastHit, Visitor } from '../types'

const quiet = quietFixture as {
  canaries: { canaries: Canary[] }
  visitors: { visitors: Visitor[] }
  trace: { now: string; last_hit: LastHit | null }
}
const silent = silentFixture as typeof quiet
const night = nightFixture as typeof quiet
const alerts = alertsFixture as typeof quiet

describe('the footer sentence per state (issue #38)', () => {
  it('quiet fixture matches gen.py\'s .foot', () => {
    const f = computeFooter(quiet.canaries.canaries, quiet.visitors.visitors, '14d', quiet.trace.now, quiet.trace.last_hit)
    expect(plainText(f)).toBe('twenty-three quiet days · all four phoning home · nothing to act on')
  })

  it('silent fixture matches gen.py\'s .foot', () => {
    const f = computeFooter(silent.canaries.canaries, silent.visitors.visitors, '14d', silent.trace.now, silent.trace.last_hit)
    expect(plainText(f)).toBe(
      'twenty-three quiet days · one canary has stopped talking — silence is only good news while the heartbeat keeps coming',
    )
  })

  it('night fixture matches gen.py\'s .foot', () => {
    const f = computeFooter(night.canaries.canaries, night.visitors.visitors, '14d', night.trace.now)
    expect(plainText(f)).toBe('a quiet fortnight until 21:55 tonight — one address is walking the cage right now')
  })
})

// issue #45: the footer may not read "nothing to act on" while a
// health state is live. Ranked by the same worstCanary the hero uses.
describe('the footer under issue #45 health states', () => {
  function canary(id: string, status: Canary['status']): Canary {
    return { id, name: id, lane: 'lan', ports: '', status, last_heartbeat_at: null, hits: 0 }
  }
  const lastHit = alerts.trace.last_hit
  const now = alerts.trace.now

  it('alerts fixture: counts all four, sends the operator to the conflict first', () => {
    const f = computeFooter(alerts.canaries.canaries, alerts.visitors.visitors, '14d', now, lastHit)
    expect(plainText(f)).toBe('thirty-five quiet days · four canaries need attention — look at canary-iot first')
    expect(f.find((seg) => seg.text === 'look at canary-iot first')?.cls).toBe('r')
    expect(f.find((seg) => seg.text === 'four canaries need attention')?.bold).toBe(true)
  })

  it('one conflicted canary alone: the ratified next step, in the alarm colour', () => {
    const f = computeFooter([canary('canary-iot', 'token_conflict'), canary('canary-lan', 'ok')], [], '14d', now, lastHit)
    expect(plainText(f)).toBe('thirty-five quiet days · canary-iot needs attention — look at the box now')
    expect(f.find((seg) => seg.text === 'look at the box now')?.cls).toBe('r')
  })

  it('a lesser state alone: named, no act-now clause', () => {
    const f = computeFooter([canary('canary-srv', 'throttled'), canary('canary-lan', 'ok')], [], '14d', now, lastHit)
    expect(plainText(f)).toBe(
      'thirty-five quiet days · canary-srv needs attention — quiet is only good news while the cage is sound',
    )
  })

  it('silent still owns its own footer when it is the worst state', () => {
    const f = computeFooter([canary('canary-iot', 'silent'), canary('canary-guest', 'rotation_stalled')], [], '14d', now, lastHit)
    expect(plainText(f)).toContain('one canary has stopped talking')
  })

  it('a conflict outranks silent and counts it', () => {
    const f = computeFooter([canary('canary-iot', 'silent'), canary('canary-srv', 'token_conflict')], [], '14d', now, lastHit)
    expect(plainText(f)).toBe('thirty-five quiet days · two canaries need attention — look at canary-srv first')
  })
})
