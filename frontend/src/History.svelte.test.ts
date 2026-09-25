// The decisions History.svelte itself makes (as opposed to lib/history/model.ts,
// already covered by model.test.ts): which of the three states (failed / empty /
// rows) is shown, what the badge count says, and whether a span reads as
// clipped or still-open. Not a snapshot of the exact sentence -- each test
// asserts one decision.
import { render, screen } from '@testing-library/svelte'
import { describe, expect, it } from 'vitest'
import History from './History.svelte'
import type { HistoryPeriod, HistoryResponse, HistorySummary } from './lib/types'

function summary(overrides: Partial<HistorySummary>): HistorySummary {
  return { canary_id: 'c1', canary_name: 'canary-lan', state: 'silent', count: 1, longest_s: 60, total_s: 60, ...overrides }
}

function period(overrides: Partial<HistoryPeriod>): HistoryPeriod {
  return {
    canary_id: 'c1',
    canary_name: 'canary-lan',
    state: 'silent',
    started_at: '2026-09-12T01:00:00Z',
    ended_at: '2026-09-12T02:00:00Z',
    flap_count: 1,
    end_reason: 'cleared',
    ...overrides,
  }
}

const WINDOW = { since: '2026-09-12T00:00:00Z', until: '2026-09-12T04:00:00Z' }

describe('History.svelte: which state renders', () => {
  it('failed takes priority over everything else, even with rows to show', () => {
    const history: HistoryResponse = { range: '24h', ...WINDOW, periods: [period({})], summary: [summary({})] }
    render(History, { history, failed: true, range: '24h' })
    expect(screen.getByText('unavailable')).toBeTruthy()
    expect(screen.getByText(/not answering/)).toBeTruthy()
    expect(screen.queryByText(/Nothing recorded/)).toBeNull()
  })

  it('no response yet (history null): reads as empty, not failed, and falls back to the requested range', () => {
    render(History, { history: null, failed: false, range: '1h' })
    expect(screen.getByText('none')).toBeTruthy()
    expect(screen.getByText(/Nothing recorded yet/)).toBeTruthy()
    expect(screen.getByText(/1 h/)).toBeTruthy()
  })

  it('a response with no periods or summary also reads as empty, using the response\'s own range', () => {
    const history: HistoryResponse = { range: '90d', ...WINDOW, periods: [], summary: [] }
    render(History, { history, failed: false, range: '1h' })
    expect(screen.getByText('none')).toBeTruthy()
    // The response's range (90 d), not the stale requested one (1 h).
    expect(screen.getByText(/90 d/)).toBeTruthy()
    expect(screen.queryByText(/1 h/)).toBeNull()
  })

  it('a response with rows: badge counts canaries, one row per canary, no empty/failed copy', () => {
    const history: HistoryResponse = {
      range: '24h',
      ...WINDOW,
      periods: [period({ canary_id: 'c1', canary_name: 'canary-lan' }), period({ canary_id: 'c2', canary_name: 'canary-srv' })],
      summary: [summary({ canary_id: 'c1', canary_name: 'canary-lan' }), summary({ canary_id: 'c2', canary_name: 'canary-srv' })],
    }
    const { container } = render(History, { history, failed: false, range: '24h' })
    expect(screen.getByText('2')).toBeTruthy()
    expect(screen.getByText(/agents/)).toBeTruthy()
    expect(screen.queryByText(/Nothing recorded/)).toBeNull()
    expect(container.querySelectorAll('.row:not(.axis-row)')).toHaveLength(2)
  })
})

describe('History.svelte: a span reads as open or clipped', () => {
  it('an open period (ended_at null) gets the open class; a closed one does not', () => {
    const history: HistoryResponse = {
      range: '24h',
      ...WINDOW,
      periods: [
        period({ canary_id: 'c1', state: 'throttled', started_at: '2026-09-12T01:00:00Z', ended_at: null }),
        period({ canary_id: 'c1', state: 'rotation_stalled', started_at: '2026-09-12T02:30:00Z', ended_at: '2026-09-12T03:00:00Z' }),
      ],
      summary: [],
    }
    const { container } = render(History, { history, failed: false, range: '24h' })
    const spans = Array.from(container.querySelectorAll<HTMLElement>('.span'))
    expect(spans.some((s) => s.classList.contains('open'))).toBe(true)
    expect(spans.some((s) => !s.classList.contains('open'))).toBe(true)
  })

  it('a period that started before the window gets the clipped class', () => {
    const history: HistoryResponse = {
      range: '24h',
      ...WINDOW,
      periods: [period({ canary_id: 'c1', started_at: '2026-09-11T22:00:00Z', ended_at: '2026-09-12T01:00:00Z' })],
      summary: [],
    }
    const { container } = render(History, { history, failed: false, range: '24h' })
    const span = container.querySelector<HTMLElement>('.span')
    expect(span?.classList.contains('clipped')).toBe(true)
  })
})
