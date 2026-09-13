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
