import { describe, expect, it } from 'vitest'
import quietFixture from '../../dev/fixtures/quiet.json'
import silentFixture from '../../dev/fixtures/silent.json'
import nightFixture from '../../dev/fixtures/night.json'
import { computeFooter } from './footer'
import { plainText } from './types'
import type { Canary, Visitor } from '../types'

const quiet = quietFixture as { canaries: { canaries: Canary[] }; visitors: { visitors: Visitor[] }; trace: { now: string } }
const silent = silentFixture as typeof quiet
const night = nightFixture as typeof quiet

describe('the footer sentence per state (issue #38)', () => {
  it('quiet fixture matches gen.py\'s .foot', () => {
    const f = computeFooter(quiet.canaries.canaries, quiet.visitors.visitors, '14d', quiet.trace.now)
    expect(plainText(f)).toBe('twenty-three quiet days · all four phoning home · nothing to act on')
  })

  it('silent fixture matches gen.py\'s .foot', () => {
    const f = computeFooter(silent.canaries.canaries, silent.visitors.visitors, '14d', silent.trace.now)
    expect(plainText(f)).toBe(
      'twenty-three quiet days · one canary has stopped talking — silence is only good news while the heartbeat keeps coming',
    )
  })

  it('night fixture matches gen.py\'s .foot', () => {
    const f = computeFooter(night.canaries.canaries, night.visitors.visitors, '14d', night.trace.now)
    expect(plainText(f)).toBe('a quiet fortnight until 21:55 tonight — one address is walking the cage right now')
  })
})
