import { describe, expect, it } from 'vitest'
import quietFixture from '../../dev/fixtures/quiet.json'
import silentFixture from '../../dev/fixtures/silent.json'
import nightFixture from '../../dev/fixtures/night.json'
import { computeSentence, plainText } from './index'
import type { Canary, Visitor } from '../types'

const quiet = quietFixture as { canaries: { canaries: Canary[] }; visitors: { visitors: Visitor[] }; trace: { now: string } }
const silent = silentFixture as typeof quiet
const night = nightFixture as typeof quiet

describe('rule 1 -- a sweep with still_arriving (night fixture)', () => {
  it('hero: One address is walking the cage.', () => {
    const s = computeSentence(night.canaries.canaries, night.visitors.visitors, '14d', night.trace.now)
    expect(s.rule).toBe(1)
    expect(plainText(s.hero)).toBe('One address is walking the cage.')
  })

  it('sub matches NIGHT_SUB from gen.py', () => {
    const s = computeSentence(night.canaries.canaries, night.visitors.visitors, '14d', night.trace.now)
    expect(plainText(s.sub)).toBe(
      '203.0.113.42 has reached all four canaries in nine minutes — ssh, then mysql, default passwords — ' +
        'and is still arriving. Three more visitors in the fortnight. Nothing here blocks: lookback in mikroview ▸ to act.',
    )
  })

  it('colours the ip and the count clause', () => {
    const s = computeSentence(night.canaries.canaries, night.visitors.visitors, '14d', night.trace.now)
    expect(s.sub.find((seg) => seg.text === '203.0.113.42')?.cls).toBe('ip')
    expect(s.sub.some((seg) => seg.bold && seg.text.includes('nine minutes'))).toBe(true)
  })
})

describe('rule 2 -- any silent canary (silent fixture)', () => {
  it('hero: Quiet for 23 days — but canary-iot is silent.', () => {
    const s = computeSentence(silent.canaries.canaries, silent.visitors.visitors, '14d', silent.trace.now)
    expect(s.rule).toBe(2)
    expect(plainText(s.hero)).toBe('Quiet for 23 days — but canary-iot is silent.')
  })

  it('sub matches SILENT_SUB from gen.py', () => {
    const s = computeSentence(silent.canaries.canaries, silent.visitors.visitors, '14d', silent.trace.now)
    expect(plainText(s.sub)).toBe(
      'Its last heartbeat was 21:58:19, six minutes ago; it phones home every minute. A silent canary is not the ' +
        'quiet we want — the host may be down, or its firewall rule on the router may have moved. The other three are fine.',
    )
  })

  it('the day count is bold and --ok', () => {
    const s = computeSentence(silent.canaries.canaries, silent.visitors.visitors, '14d', silent.trace.now)
    const days = s.hero.find((seg) => seg.text === '23 days')
    expect(days?.bold).toBe(true)
    expect(days?.cls).toBe('ok')
  })
})

describe('rule 3 -- visitors in range, none tonight (hand-built)', () => {
  const canaries: Canary[] = [
    { id: 'canary-lan', name: 'canary-lan', lane: 'lan', ports: 'ssh 22 · http 80', status: 'ok', last_heartbeat_at: null, hits: 3 },
    { id: 'canary-srv', name: 'canary-srv', lane: 'srv', ports: 'ssh 22 · ftp 21', status: 'ok', last_heartbeat_at: null, hits: 1 },
  ]
  const visitors: Visitor[] = [
    {
      source_ip: '203.0.113.9',
      kind: 'sweep',
      first_at: '2026-09-10T10:00:00Z',
      last_at: '2026-09-10T10:05:00Z',
      hits: 2,
      canaries: [
        { id: 'canary-lan', hits: 1 },
        { id: 'canary-srv', hits: 1 },
      ],
      services: ['ssh'],
      tried: ['root / root'],
      still_arriving: false,
    },
    {
      source_ip: '198.51.100.4',
      kind: 'touch',
      first_at: '2026-09-11T03:00:00Z',
      last_at: '2026-09-11T03:00:00Z',
      hits: 1,
      canaries: [{ id: 'canary-srv', hits: 1 }],
      services: ['ftp'],
      tried: ['anonymous / (empty)'],
      still_arriving: false,
    },
  ]
  const now = '2026-09-12T00:00:00Z'

  it('picks rule 3 when visitors exist but none is a still-arriving sweep', () => {
    const s = computeSentence(canaries, visitors, '14d', now)
    expect(s.rule).toBe(3)
  })

  it('hero: N visitors in the fortnight, none tonight.', () => {
    const s = computeSentence(canaries, visitors, '14d', now)
    expect(plainText(s.hero)).toBe('Two visitors in the fortnight, none tonight.')
  })

  it('one line per kind present', () => {
    const s = computeSentence(canaries, visitors, '14d', now)
    const text = plainText(s.sub)
    expect(text).toContain('One address swept all two canaries on Thursday.')
    expect(text).toContain('198.51.100.4 touched canary-srv :21, once.')
  })
})

describe('rule 4 -- nothing (quiet fixture)', () => {
  it('hero: Quiet for 23 days.', () => {
    const s = computeSentence(quiet.canaries.canaries, quiet.visitors.visitors, '14d', quiet.trace.now)
    expect(s.rule).toBe(4)
    expect(plainText(s.hero)).toBe('Quiet for 23 days.')
  })

  it('sub matches QUIET_SUB from gen.py', () => {
    const s = computeSentence(quiet.canaries.canaries, quiet.visitors.visitors, '14d', quiet.trace.now)
    expect(plainText(s.sub)).toBe(
      'Nothing has touched a canary since Thu 13 Aug — one touch on canary-guest :23 from 198.51.100.200, cleared ' +
        'with a note. The four canaries have phoned home every minute since; the newest heartbeat was three seconds ago.',
    )
  })
})
