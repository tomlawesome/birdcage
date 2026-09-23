import { describe, expect, it } from 'vitest'
import quietFixture from '../../dev/fixtures/quiet.json'
import silentFixture from '../../dev/fixtures/silent.json'
import nightFixture from '../../dev/fixtures/night.json'
import { computeSentence, plainText } from './index'
import type { Canary, LastHit, Visitor } from '../types'

const quiet = quietFixture as {
  canaries: { canaries: Canary[] }
  visitors: { visitors: Visitor[] }
  trace: { now: string; last_hit: LastHit | null }
}
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
    const s = computeSentence(silent.canaries.canaries, silent.visitors.visitors, '14d', silent.trace.now, silent.trace.last_hit)
    expect(s.rule).toBe(2)
    expect(plainText(s.hero)).toBe('Quiet for 23 days — but canary-iot is silent.')
  })

  it('sub matches SILENT_SUB from gen.py', () => {
    const s = computeSentence(silent.canaries.canaries, silent.visitors.visitors, '14d', silent.trace.now, silent.trace.last_hit)
    expect(plainText(s.sub)).toBe(
      'Its last heartbeat was 21:58:19, six minutes ago; it phones home every minute. A silent canary is not the ' +
        'quiet we want — the host may be down, or its firewall rule on the router may have moved. The other three are fine.',
    )
  })

  it('the day count is bold and --ok', () => {
    const s = computeSentence(silent.canaries.canaries, silent.visitors.visitors, '14d', silent.trace.now, silent.trace.last_hit)
    const days = s.hero.find((seg) => seg.text === '23 days')
    expect(days?.bold).toBe(true)
    expect(days?.cls).toBe('ok')
  })

  it('with no last_hit the hero is only the silence, never "Quiet for 0 days"', () => {
    const s = computeSentence(silent.canaries.canaries, silent.visitors.visitors, '14d', silent.trace.now, null)
    expect(s.rule).toBe(2)
    expect(plainText(s.hero)).toBe('Nothing has touched a canary — but canary-iot is silent.')
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
    const s = computeSentence(quiet.canaries.canaries, quiet.visitors.visitors, '14d', quiet.trace.now, quiet.trace.last_hit)
    expect(s.rule).toBe(4)
    expect(plainText(s.hero)).toBe('Quiet for 23 days.')
  })

  it('sub built from last_hit, no "cleared with a note" clause', () => {
    const s = computeSentence(quiet.canaries.canaries, quiet.visitors.visitors, '14d', quiet.trace.now, quiet.trace.last_hit)
    expect(plainText(s.sub)).toBe(
      'Nothing has touched a canary since Thu 13 Aug — one touch on canary-guest :23 from 198.51.100.200. ' +
        'The four canaries have phoned home every minute since; the newest heartbeat was three seconds ago.',
    )
  })

  it('last_hit null: shortest wording, no date to build a day count or a since-clause from', () => {
    const s = computeSentence(quiet.canaries.canaries, quiet.visitors.visitors, '14d', quiet.trace.now, null)
    expect(s.rule).toBe(4)
    expect(plainText(s.hero)).toBe('Nothing has ever touched a canary.')
    expect(plainText(s.sub)).toBe(
      'The four canaries have phoned home every minute since; the newest heartbeat was three seconds ago.',
    )
  })
})

// issue #45 -- the health states that widen rule 2's slot. Hand-built
// like rule 3 and status.test.ts's ranking cases: no fixture covers the
// new states yet, and building canaries directly isolates the copy and
// the ranking from fixture detail.
describe('rule 2 -- issue #45 health states (hand-built)', () => {
  function canary(id: string, status: Canary['status'], extra: Partial<Canary> = {}): Canary {
    return {
      id,
      name: id,
      lane: 'lan',
      ports: 'ssh 22',
      status,
      last_heartbeat_at: '2026-09-05T22:04:00Z',
      hits: 0,
      ...extra,
    }
  }
  // Same 23-day quiet story shape the quiet/silent fixtures carry.
  const lastHit: LastHit = {
    at: '2026-08-13T21:14:09Z',
    visitor: '198.51.100.200',
    canary: 'canary-guest',
    port: 23,
    service: 'telnet',
    kind: 'touch',
  }
  const now = '2026-09-05T22:04:31Z'
  const fleet = (bad: Canary): Canary[] => [canary('canary-lan', 'ok'), canary('canary-srv', 'ok'), bad, canary('canary-guest', 'ok')]

  it('token conflict: hero and sub', () => {
    const bad = canary('canary-iot', 'token_conflict', { token_conflict_for_s: 300 })
    const s = computeSentence(fleet(bad), [], '14d', now, lastHit)
    expect(s.rule).toBe(2)
    expect(plainText(s.hero)).toBe("Quiet for 23 days — but canary-iot's revoked token came back.")
    expect(plainText(s.sub)).toBe(
      'It was presented five minutes ago, while its successor was already active. Either the token was stolen ' +
        'and the thief rotated first, or two boxes share one identity. Look at the box now. The other three are fine.',
    )
    expect(s.sub.find((seg) => seg.text === 'five minutes ago')?.bold).toBe(true)
    expect(s.sub.find((seg) => seg.text === 'Look at the box now.')?.bold).toBe(true)
  })

  it('not delivering: hero and sub', () => {
    const bad = canary('canary-iot', 'not_delivering', { not_delivering: true })
    const s = computeSentence(fleet(bad), [], '14d', now, lastHit)
    expect(s.rule).toBe(2)
    expect(plainText(s.hero)).toBe('Quiet for 23 days — but canary-iot is not delivering.')
    expect(plainText(s.sub)).toBe(
      "Its heartbeats arrive on time, but its agent can't read OpenCanary's log, so whatever the canary catches " +
        'never reaches this page — which would read just the same if the canary were catching someone right now. ' +
        'Check the agent on the box. The other three are fine.',
    )
  })

  it('throttled: hero and sub, delay not loss', () => {
    const bad = canary('canary-iot', 'throttled', { throttled_for_s: 120 })
    const s = computeSentence(fleet(bad), [], '14d', now, lastHit)
    expect(s.rule).toBe(2)
    expect(plainText(s.hero)).toBe('Quiet for 23 days — but canary-iot is throttled.')
    expect(plainText(s.sub)).toBe(
      'It crossed its rate limit two minutes ago and birdcage refused part of what it sent — delay, not loss: ' +
        'the events wait in its log. Either its agent is broken, or that box is under an attack larger than ' +
        'anything planned for. Go and see which. The other three are fine.',
    )
  })

  it('rotation stalled, not escalated: names the issued, unused token', () => {
    const bad = canary('canary-iot', 'rotation_stalled', { rotation_stalled: true, rotation_stalled_for_s: 1200 })
    const s = computeSentence(fleet(bad), [], '14d', now, lastHit)
    expect(s.rule).toBe(2)
    expect(plainText(s.hero)).toBe("Quiet for 23 days — but canary-iot's token rotation has stalled.")
    expect(plainText(s.sub)).toBe(
      "Birdcage issued it a fresh token 20 minutes ago and the agent hasn't picked it up. It still phones home " +
        'every minute on the old token — nothing is being missed, but a protection has quietly lapsed. ' +
        'Check the agent. The other three are fine.',
    )
  })

  it('rotation stalled, escalated: claims only what both triggers make true', () => {
    const bad = canary('canary-iot', 'rotation_stalled', {
      rotation_stalled: true,
      rotation_stalled_for_s: 93600,
      rotation_stalled_escalated: true,
    })
    const s = computeSentence(fleet(bad), [], '14d', now, lastHit)
    const text = plainText(s.sub)
    expect(text).toContain("It hasn't completed a rotation in over a day.")
    expect(text).not.toContain('fresh token')
    expect(text).toContain('nothing is being missed')
  })

  it('durations past the hour read in hours, not minutes', () => {
    const bad = canary('canary-iot', 'token_conflict', { token_conflict_for_s: 72000 })
    const s = computeSentence(fleet(bad), [], '14d', now, lastHit)
    expect(plainText(s.sub)).toContain('It was presented 20 hours ago')
  })

  it('with no last_hit the opener is the contrast alone, as rule 2 already does', () => {
    const bad = canary('canary-iot', 'throttled', { throttled_for_s: 120 })
    const s = computeSentence(fleet(bad), [], '14d', now, null)
    expect(plainText(s.hero)).toBe('Nothing has touched a canary — but canary-iot is throttled.')
  })

  it('a still-arriving sweep outranks every health state, as it already outranked silent', () => {
    const bad = canary('canary-iot', 'token_conflict', { token_conflict_for_s: 300 })
    const sweep: Visitor = {
      source_ip: '203.0.113.42',
      kind: 'sweep',
      first_at: '2026-09-05T21:55:00Z',
      last_at: '2026-09-05T22:04:00Z',
      hits: 7,
      canaries: [{ id: 'canary-lan', hits: 2 }],
      services: ['ssh'],
      tried: ['root / root'],
      still_arriving: true,
    }
    const s = computeSentence(fleet(bad), [sweep], '14d', now, lastHit)
    expect(s.rule).toBe(1)
  })

  it('a health state outranks the visitor recap, as silent already did', () => {
    const bad = canary('canary-iot', 'rotation_stalled', { rotation_stalled: true, rotation_stalled_for_s: 1200 })
    const touch: Visitor = {
      source_ip: '198.51.100.4',
      kind: 'touch',
      first_at: '2026-09-05T03:00:00Z',
      last_at: '2026-09-05T03:00:00Z',
      hits: 1,
      canaries: [{ id: 'canary-srv', hits: 1 }],
      services: ['ssh'],
      tried: ['root / root'],
      still_arriving: false,
    }
    const s = computeSentence(fleet(bad), [touch], '14d', now, lastHit)
    expect(s.rule).toBe(2)
    expect(plainText(s.hero)).toContain('token rotation has stalled')
  })

  it('token conflict outranks silent; silent keeps its own copy over lesser states', () => {
    const conflicted = computeSentence(
      [canary('canary-iot', 'silent', { silent_for_s: 372 }), canary('canary-srv', 'token_conflict', { token_conflict_for_s: 300 })],
      [],
      '14d',
      now,
      lastHit,
    )
    expect(plainText(conflicted.hero)).toContain("canary-srv's revoked token came back")

    const silenced = computeSentence(
      [
        canary('canary-lan', 'not_delivering', { not_delivering: true }),
        canary('canary-iot', 'silent', { silent_for_s: 372 }),
        canary('canary-srv', 'rotation_stalled', { rotation_stalled: true, rotation_stalled_for_s: 1200 }),
      ],
      [],
      '14d',
      now,
      lastHit,
    )
    expect(plainText(silenced.hero)).toContain('canary-iot is silent.')
  })

  it('not delivering outranks throttled', () => {
    const s = computeSentence(
      [canary('canary-lan', 'throttled', { throttled_for_s: 120 }), canary('canary-srv', 'not_delivering', { not_delivering: true })],
      [],
      '14d',
      now,
      lastHit,
    )
    expect(plainText(s.hero)).toContain('canary-srv is not delivering.')
  })

  it('"the other N are fine" is earned: absent when another canary is not ok', () => {
    const s = computeSentence(
      [
        canary('canary-iot', 'token_conflict', { token_conflict_for_s: 300 }),
        canary('canary-srv', 'throttled', { throttled_for_s: 120 }),
        canary('canary-lan', 'ok'),
      ],
      [],
      '14d',
      now,
      lastHit,
    )
    expect(plainText(s.hero)).toContain('revoked token came back')
    expect(plainText(s.sub)).not.toContain('The other')
  })

  it('a fleet of one has no others to vouch for', () => {
    const s = computeSentence([canary('canary-iot', 'throttled', { throttled_for_s: 120 })], [], '14d', now, lastHit)
    expect(plainText(s.sub)).not.toContain('The other')
    expect(plainText(s.sub)).toContain('Go and see which.')
  })

  it('a fleet of two says "is", not "are"', () => {
    const s = computeSentence(
      [canary('canary-iot', 'throttled', { throttled_for_s: 120 }), canary('canary-srv', 'ok')],
      [],
      '14d',
      now,
      lastHit,
    )
    expect(plainText(s.sub)).toContain('The other one is fine.')
  })

  // Issue #47 steps 7-9: rule 2's switch has no case for 'pending' --
  // #45's own "hero-sentence prose is a separate design call" applies
  // here too, so a fleet whose only issue is one pending canary falls
  // through to rule 4's ordinary quiet story, not a fault sentence. The
  // dashboard tile still says "pending" (Tiles.svelte); this pins that
  // the hero voice deliberately does not, until that copy is written.
  it('a lone pending canary does not trigger rule 2', () => {
    const s = computeSentence([canary('canary-iot', 'pending')], [], '14d', now, lastHit)
    expect(s.rule).toBe(4)
  })

  it('rotation stalled still outranks pending', () => {
    const s = computeSentence(
      [
        canary('canary-lan', 'pending'),
        canary('canary-srv', 'rotation_stalled', { rotation_stalled: true, rotation_stalled_for_s: 1200 }),
      ],
      [],
      '14d',
      now,
      lastHit,
    )
    expect(plainText(s.hero)).toContain("canary-srv's token rotation has stalled")
  })
})
