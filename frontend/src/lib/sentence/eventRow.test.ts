import { describe, expect, it } from 'vitest'
import { buildEventRows, computeEventRow, computeEventsHeading, type EventAction } from './eventRow'
import { plainText } from './types'
import type { Canary, Visitor, VisitorKind } from '../types'

// Hand-built canaries and visitors (like rules.test.ts's rule-3 and issue #45
// blocks) so each test isolates one branch of eventRow's decision logic from
// fixture noise -- night.json only carries one visitor per kind, with fixed
// timestamps that can't show the still-arriving / day-boundary / interval
// edges below.

const canaries: Canary[] = [
  { id: 'canary-lan', name: 'canary-lan', lane: 'lan', ports: 'ssh 22 · http 80 · smb 445', status: 'ok', last_heartbeat_at: null, hits: 0 },
  { id: 'canary-srv', name: 'canary-srv', lane: 'srv', ports: 'ssh 22 · mysql 3306 · ftp 21', status: 'ok', last_heartbeat_at: null, hits: 0 },
]

function visitor(overrides: Partial<Visitor> & { kind: VisitorKind }): Visitor {
  return {
    source_ip: '203.0.113.9',
    first_at: '2026-09-12T21:00:00Z',
    last_at: '2026-09-12T21:00:00Z',
    hits: 1,
    canaries: [{ id: 'canary-lan', hits: 1 }],
    services: ['ssh'],
    tried: ['root / root'],
    still_arriving: false,
    ...overrides,
  }
}

describe('timeColumn: a different day than now', () => {
  it('uses the relative day label and the raw clock, not an elapsed-time label', () => {
    const v = visitor({ kind: 'touch', first_at: '2026-09-10T03:18:40Z', last_at: '2026-09-10T03:18:40Z' })
    const row = computeEventRow(v, canaries, '2026-09-12T22:04:31Z')
    expect(row.time.primary).toBe('2 days ago')
    expect(row.time.small).toBe('03:18:40')
  })
})

describe('timeColumn: a still-arriving sweep, same day', () => {
  it('shows "N m · still arriving", not an elapsed-time label', () => {
    const v = visitor({ kind: 'sweep', still_arriving: true, first_at: '2026-09-12T21:55:00Z', last_at: '2026-09-12T22:04:00Z' })
    const row = computeEventRow(v, canaries, '2026-09-12T22:04:00Z')
    expect(row.time.primary).toBe('22:04:00')
    expect(row.time.small).toBe('9 m · still arriving')
  })
})

describe('timeColumn: a repeat visitor, same day', () => {
  it('counts calendar nights between first and last contact, inclusive', () => {
    // Sep 10 -> Sep 12 is 2 calendar days apart, so 3 nights running.
    const v = visitor({ kind: 'repeat', first_at: '2026-09-10T08:00:00Z', last_at: '2026-09-12T22:04:00Z' })
    const row = computeEventRow(v, canaries, '2026-09-12T22:04:00Z')
    expect(row.time.primary).toBe('22:04:00')
    expect(row.time.small).toBe('3 nights · on schedule')
  })
})

describe('timeColumn: elapsed time (touch/inside/sweep-not-still-arriving), same day', () => {
  it('well under the rounding threshold shows minutes', () => {
    const v = visitor({ kind: 'touch', last_at: '2026-09-12T21:52:00Z' })
    const row = computeEventRow(v, canaries, '2026-09-12T22:04:00Z')
    expect(row.time.small).toBe('12 m ago')
  })

  it('45 minutes rounds up to 1 hour, crossing the hours>=1 threshold', () => {
    // Math.round(45/60) = Math.round(0.75) = 1, so this is the real
    // boundary case: one minute later and it would already read "1 h ago".
    const v = visitor({ kind: 'touch', last_at: '2026-09-12T21:19:00Z' })
    const row = computeEventRow(v, canaries, '2026-09-12T22:04:00Z')
    expect(row.time.small).toBe('1 h ago')
  })

  it('90 minutes rounds to 2 hours, not floors to 1', () => {
    const v = visitor({ kind: 'inside', last_at: '2026-09-12T20:34:00Z' })
    const row = computeEventRow(v, canaries, '2026-09-12T22:04:00Z')
    expect(row.time.small).toBe('2 h ago')
  })
})

describe('whoSentence: sweep "never seen before tonight"', () => {
  it('appends the clause when still arriving and first contact was today', () => {
    const v = visitor({
      kind: 'sweep',
      still_arriving: true,
      first_at: '2026-09-12T21:55:00Z',
      last_at: '2026-09-12T22:04:00Z',
    })
    const row = computeEventRow(v, canaries, '2026-09-12T22:04:00Z')
    expect(plainText(row.who)).toContain(' Never seen before tonight.')
  })

  it('omits the clause when not still arriving, even if first contact was today', () => {
    const v = visitor({
      kind: 'sweep',
      still_arriving: false,
      first_at: '2026-09-12T21:55:00Z',
      last_at: '2026-09-12T22:04:00Z',
    })
    const row = computeEventRow(v, canaries, '2026-09-12T22:04:00Z')
    expect(plainText(row.who)).not.toContain('Never seen before tonight')
  })

  it('omits the clause when still arriving but first contact crossed a UTC day boundary', () => {
    const v = visitor({
      kind: 'sweep',
      still_arriving: true,
      first_at: '2026-09-11T23:55:00Z',
      last_at: '2026-09-12T00:04:00Z',
    })
    const row = computeEventRow(v, canaries, '2026-09-12T00:04:00Z')
    expect(plainText(row.who)).not.toContain('Never seen before tonight')
  })
})

describe('whoSentence: repeat interval arithmetic', () => {
  it('reflects hits and span for a picked example (120 min span, 4 hits -> ~40 min interval)', () => {
    // spanMinutes = round((22:00 - 20:00) / 60000) = 120
    // interval = round(120 / max(1, 4 - 1)) = round(120 / 3) = 40
    const v = visitor({
      kind: 'repeat',
      first_at: '2026-09-12T20:00:00Z',
      last_at: '2026-09-12T22:00:00Z',
      hits: 4,
      canaries: [{ id: 'canary-srv', hits: 4 }],
      services: ['mysql'],
    })
    const row = computeEventRow(v, canaries, '2026-09-12T22:00:00Z')
    expect(plainText(row.who)).toContain('every ~40 minutes')
  })
})

describe('whoSentence: inside bolds the last tried path, not the first', () => {
  it('bolds tried[tried.length - 1]', () => {
    const v = visitor({
      kind: 'inside',
      tried: ['/', '/admin', '/config'],
      canaries: [{ id: 'canary-lan', hits: 3 }],
      services: ['http'],
    })
    const row = computeEventRow(v, canaries, '2026-09-12T22:04:00Z')
    const bolded = row.who.find((seg) => seg.bold)
    expect(bolded?.text).toBe('/config')
  })
})

describe('whoSentence: touch credential is the part before the slash', () => {
  it('splits tried[0] on " / " and keeps only the username', () => {
    const v = visitor({
      kind: 'touch',
      tried: ['administrator / hunter2'],
      canaries: [{ id: 'canary-srv', hits: 1 }],
      services: ['ftp'],
    })
    const row = computeEventRow(v, canaries, '2026-09-12T22:04:00Z')
    expect(plainText(row.who)).toContain('as administrator,')
    expect(plainText(row.who)).not.toContain('hunter2')
  })
})

describe('defaultActions: one action set per kind', () => {
  const cases: [VisitorKind, EventAction[]][] = [
    ['sweep', [{ label: 'lookback in mikroview ▸' }, { label: 'raw lines ▸' }]],
    ['repeat', [{ label: 'already blocked', quiet: true }]],
    ['inside', [{ label: 'which device? ▸' }]],
    ['touch', [{ label: 'clear with a note', quiet: true }]],
  ]

  it.each(cases)('%s gets its own fixed action set', (kind, expected) => {
    const v = visitor({ kind })
    const row = computeEventRow(v, canaries, '2026-09-12T22:04:00Z')
    expect(row.actions).toEqual(expected)
  })
})

describe('buildEventRows: Events.svelte\'s merge-and-sort decision (#74)', () => {
  it('interleaves a dropped-out canary among visitor rows by its own timestamp, newest first', () => {
    const silent: Canary = { ...canaries[0], status: 'silent', last_heartbeat_at: '2026-09-12T21:30:00Z' }
    const others = [canaries[1]]
    const older = visitor({ kind: 'touch', last_at: '2026-09-12T21:00:00Z' })
    const newer = visitor({ kind: 'inside', last_at: '2026-09-12T22:00:00Z' })
    const rows = buildEventRows([silent, ...others], [older, newer], '2026-09-12T22:04:00Z')
    // Newest first: the 22:00 visitor, then the 21:30 dropout, then the 21:00 visitor.
    expect(rows.map((r) => r.key)).toEqual([
      `${newer.source_ip}-inside-${newer.last_at}`,
      `dropped-${silent.id}`,
      `${older.source_ip}-touch-${older.last_at}`,
    ])
  })

  it('a canary that has never sent a heartbeat sorts last, not first', () => {
    const neverHeard: Canary = { ...canaries[0], status: 'silent', last_heartbeat_at: null }
    const v = visitor({ kind: 'touch', last_at: '2026-09-12T21:00:00Z' })
    const rows = buildEventRows([neverHeard, canaries[1]], [v], '2026-09-12T22:04:00Z')
    expect(rows.map((r) => r.key)).toEqual([`${v.source_ip}-touch-${v.last_at}`, `dropped-${neverHeard.id}`])
  })

  it('no silent canaries: only visitor rows, no dropped-out row', () => {
    const v = visitor({ kind: 'touch' })
    const rows = buildEventRows(canaries, [v], '2026-09-12T22:04:00Z')
    expect(rows).toHaveLength(1)
    expect(rows[0].cls).not.toBe('k-off')
  })

  it('no visitors: only dropped-out rows, one per silent canary', () => {
    const silent: Canary = { ...canaries[0], status: 'silent', last_heartbeat_at: '2026-09-12T21:30:00Z' }
    const rows = buildEventRows([silent, canaries[1]], [], '2026-09-12T22:04:00Z')
    expect(rows).toEqual([expect.objectContaining({ key: `dropped-${silent.id}`, cls: 'k-off' })])
  })
})

describe('computeEventsHeading', () => {
  it('no visitors and no silent canaries: "none", quiet line shown', () => {
    const h = computeEventsHeading(canaries, [], '14d')
    expect(plainText(h.segments)).toBe('events · 14 days · none')
    expect(h.showQuietLine).toBe(true)
  })

  it('no visitors but some silent canaries: counts them, no quiet line', () => {
    const withSilent: Canary[] = [{ ...canaries[0], status: 'silent' }, canaries[1]]
    const h = computeEventsHeading(withSilent, [], '14d')
    expect(plainText(h.segments)).toBe('events · 14 days · 1 · no visitors')
    expect(h.showQuietLine).toBe(false)
  })

  it('visitors present: counts them, "newest first", no quiet line', () => {
    const v = visitor({ kind: 'touch' })
    const h = computeEventsHeading(canaries, [v], '14d')
    expect(plainText(h.segments)).toBe('events · 14 days · 1 visitors · newest first')
    expect(h.showQuietLine).toBe(false)
  })
})

describe('whoSentence: poisoner answered a name nobody should answer', () => {
  const poisoned = (mac: string) =>
    visitor({
      kind: 'inside',
      source_ip: '10.30.0.51',
      services: ['poisoner'],
      tried: ['llmnr'],
      poisoner: { name: 'fs-lon-02', protocol: 'llmnr', mac },
    })

  it('says what answered, for which name, and why that matters', () => {
    const row = computeEventRow(poisoned('52:54:00:8a:1c:3d'), canaries, '2026-09-12T21:05:00Z')
    expect(plainText(row.who)).toBe(
      '10.30.0.51 answered for fs-lon-02, a name nobody should answer. llmnr · 52:54:00:8a:1c:3d',
    )
  })

  it('bolds the bait name, because it is the point -- nothing should have answered for it', () => {
    const row = computeEventRow(poisoned('52:54:00:8a:1c:3d'), canaries, '2026-09-12T21:05:00Z')
    expect(row.who.find((s) => s.bold)?.text).toBe('fs-lon-02')
  })

  it('leaves the MAC out when the canary had no neighbour entry for the answerer', () => {
    // An answer from off-segment or over IPv6 has none to read
    // (internal/agent/poisoner/arp.go), which is ordinary rather than a gap.
    const row = computeEventRow(poisoned(''), canaries, '2026-09-12T21:05:00Z')
    expect(plainText(row.who)).toBe(
      '10.30.0.51 answered for fs-lon-02, a name nobody should answer. llmnr',
    )
  })

  it('is labelled with the protocol, not with the kind it shares', () => {
    // Its kind has to be "inside" -- a link-local protocol can only be
    // answered from the segment -- but "FROM INSIDE" says nothing an operator
    // can act on where "LLMNR" says which question was answered.
    for (const [protocol, label] of [
      ['llmnr', 'LLMNR'],
      ['nbt-ns', 'NBT-NS'],
      ['mdns', 'MDNS'],
    ]) {
      const v = poisoned('52:54:00:8a:1c:3d')
      v.poisoner!.protocol = protocol
      expect(computeEventRow(v, canaries, '2026-09-12T21:05:00Z').kind.label).toBe(label)
    }
  })

  it('keeps the inside rise colour, so no fifth colour enters the palette', () => {
    // ADR-0004: the palette is the four kind colours validated in round 1.
    const row = computeEventRow(poisoned('52:54:00:8a:1c:3d'), canaries, '2026-09-12T21:05:00Z')
    expect(row.cls).toBe(computeEventRow(visitor({ kind: 'inside' }), canaries, '2026-09-12T21:05:00Z').cls)
  })

  it('leaves every other visitor untouched', () => {
    // No poisoner block means the ordinary "inside" sentence, unchanged.
    const row = computeEventRow(
      visitor({ kind: 'inside', tried: ['/admin', '/etc/passwd'] }),
      canaries,
      '2026-09-12T21:05:00Z',
    )
    expect(plainText(row.who)).toContain('browsed')
    expect(row.kind.label).toBe('FROM INSIDE')
  })
})
