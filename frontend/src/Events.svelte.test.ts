// Events.svelte's own decisions, as opposed to lib/sentence (already
// covered by eventRow.test.ts): whether the quiet-line replaces the row
// list, and whether a segment/action renders as bold, coloured, or plain.
// The merge-and-sort ordering itself is tested directly against
// buildEventRows in lib/sentence/eventRow.test.ts.
import { render, screen } from '@testing-library/svelte'
import { describe, expect, it } from 'vitest'
import Events from './Events.svelte'
import type { Canary, TraceResponse, Visitor } from './lib/types'

const trace: TraceResponse = { now: '2026-09-12T22:04:00Z', range: '24h', canaries: [], last_hit: null }

function canary(overrides: Partial<Canary> = {}): Canary {
  return {
    id: 'canary-lan',
    name: 'canary-lan',
    lane: 'lan',
    ports: 'ssh 22',
    status: 'ok',
    last_heartbeat_at: '2026-09-12T22:00:00Z',
    hits: 0,
    ...overrides,
  }
}

function visitor(overrides: Partial<Visitor> & { kind: Visitor['kind'] }): Visitor {
  return {
    source_ip: '203.0.113.9',
    first_at: '2026-09-12T21:55:00Z',
    last_at: '2026-09-12T22:00:00Z',
    hits: 1,
    canaries: [{ id: 'canary-lan', hits: 1 }],
    services: ['ssh'],
    tried: ['administrator / hunter2'],
    still_arriving: false,
    ...overrides,
  }
}

describe('Events.svelte: quiet line vs a row list', () => {
  it('nothing at all: shows the quiet line, no rows', () => {
    const { container } = render(Events, { canaries: [canary()], visitors: [], trace, range: '24h' })
    expect(screen.getByText(/only things moving on this page are the heartbeats/)).toBeTruthy()
    expect(container.querySelectorAll('.row')).toHaveLength(0)
  })

  it('a visitor present: rows render, no quiet line', () => {
    const { container } = render(Events, { canaries: [canary()], visitors: [visitor({ kind: 'touch' })], trace, range: '24h' })
    expect(screen.queryByText(/only things moving on this page/)).toBeNull()
    expect(container.querySelectorAll('.row')).toHaveLength(1)
  })

  it('no visitors but a silent canary: a DROPPED OUT row, not the quiet line', () => {
    const { container } = render(Events, {
      canaries: [canary({ status: 'silent', last_heartbeat_at: '2026-09-12T20:00:00Z' })],
      visitors: [],
      trace,
      range: '24h',
    })
    expect(screen.queryByText(/only things moving on this page/)).toBeNull()
    expect(container.querySelector('.kind')?.textContent).toContain('DROPPED OUT')
    expect(container.querySelectorAll('.row.k-off')).toHaveLength(1)
  })
})

describe('Events.svelte: a who-segment renders as bold, coloured, or plain', () => {
  it('the source IP gets the .ip class; the emphasised phrase gets bold', () => {
    const v = visitor({ kind: 'inside', tried: ['/', '/admin'] })
    const { container } = render(Events, { canaries: [canary()], visitors: [v], trace, range: '24h' })
    const who = container.querySelector('.who')
    expect(who?.querySelector('.ip')?.textContent).toBe(v.source_ip)
    // whoSentence bolds the last tried path for 'inside'.
    expect(who?.querySelector('b')?.textContent).toBe('/admin')
  })
})

describe('Events.svelte: an action pill can read quiet or not', () => {
  it('a repeat visitor\'s "already blocked" pill is quiet', () => {
    const v = visitor({ kind: 'repeat', hits: 3, first_at: '2026-09-12T20:00:00Z', last_at: '2026-09-12T22:00:00Z' })
    const { container } = render(Events, { canaries: [canary()], visitors: [v], trace, range: '24h' })
    const pill = container.querySelector('.pill')
    expect(pill?.textContent).toBe('already blocked')
    expect(pill?.classList.contains('quiet')).toBe(true)
  })

  it('a sweep visitor\'s action pills are not quiet', () => {
    const v = visitor({ kind: 'sweep' })
    const { container } = render(Events, { canaries: [canary()], visitors: [v], trace, range: '24h' })
    const pills = Array.from(container.querySelectorAll('.pill'))
    expect(pills.length).toBeGreaterThan(0)
    expect(pills.every((p) => !p.classList.contains('quiet'))).toBe(true)
  })
})
