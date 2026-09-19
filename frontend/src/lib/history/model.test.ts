// Issue #56: the summary line each case of the window produces, the
// arithmetic that puts a span on the bar (including both clipped edges
// and a period that is still open), and the tier each state carries --
// in particular that 'unobserved' never takes the alarm colour, since
// birdcage not watching is not the canary's fault.
import { describe, expect, it } from 'vitest'
import type { HistoryPeriod, HistoryResponse, HistorySummary } from '../types'
import {
  historyRangeLabel,
  historyRows,
  historyTicks,
  layoutLanes,
  placeSpan,
  spanDuration,
  summaryLine,
  tierFor,
} from './model'

// A one-day window, so a percentage reads as a fraction of the day.
const SINCE = '2026-09-16T00:00:00Z'
const UNTIL = '2026-09-17T00:00:00Z'

const period = (over: Partial<HistoryPeriod> = {}): HistoryPeriod => ({
  canary_id: 'canary-srv',
  canary_name: 'canary-srv',
  state: 'throttled',
  started_at: '2026-09-16T06:00:00Z',
  ended_at: '2026-09-16T12:00:00Z',
  flap_count: 1,
  end_reason: 'cleared',
  ...over,
})

const entry = (over: Partial<HistorySummary> = {}): HistorySummary => ({
  canary_id: 'canary-srv',
  canary_name: 'canary-srv',
  state: 'throttled',
  count: 1,
  longest_s: 660,
  total_s: 660,
  ...over,
})

describe('summaryLine -- the row\'s one line of English', () => {
  it('nothing at all: "all quiet"', () => expect(summaryLine([])).toBe('all quiet'))

  it('several spans name the count and the longest', () =>
    expect(summaryLine([entry({ count: 4, longest_s: 660, total_s: 1980 })])).toBe(
      'throttled 4 times, longest 11 m',
    ))

  it('one span drops "longest" and just says how long', () =>
    expect(summaryLine([entry({ state: 'silent', count: 1, longest_s: 12000, total_s: 12000 })])).toBe(
      'silent once, 3 h 20 m',
    ))

  it('two spans read "twice", not "2 times"', () =>
    expect(summaryLine([entry({ count: 2, longest_s: 660, total_s: 1020 })])).toContain('throttled twice'))

  it('nothing but unobserved: birdcage says it was not watching', () =>
    expect(summaryLine([entry({ state: 'unobserved', count: 1, longest_s: 7200, total_s: 7200 })])).toBe(
      'birdcage was not watching for 2 h',
    ))

  it('several states read worst first, with the unobserved clause last', () => {
    const line = summaryLine([
      entry({ state: 'unobserved', count: 1, longest_s: 7200, total_s: 7200 }),
      entry({ state: 'rotation_stalled', count: 1, longest_s: 39600, total_s: 39600 }),
      entry({ state: 'silent', count: 1, longest_s: 12000, total_s: 12000 }),
    ])
    expect(line).toBe('silent once, 3 h 20 m · rotation stalled once, 11 h · birdcage was not watching for 2 h')
  })
})

describe('spanDuration -- the summary line\'s duration voice', () => {
  it('under a minute keeps seconds, the only thing there is to say', () =>
    expect(spanDuration(45)).toBe('45 s'))
  it('minutes drop the seconds: "11 m", never "11 m 0 s"', () => expect(spanDuration(660)).toBe('11 m'))
  it('past an hour keeps the minutes: "3 h 20 m", never "3 h"', () => expect(spanDuration(12000)).toBe('3 h 20 m'))
  it('a whole number of hours drops the remainder: "2 h", never "2 h 0 m"', () =>
    expect(spanDuration(7200)).toBe('2 h'))
})

describe('placeSpan -- where one period sits on the bar', () => {
  it('a period inside the window is a plain fraction of it', () => {
    const placed = placeSpan(period(), SINCE, UNTIL)
    expect(placed).not.toBeNull()
    expect(placed?.leftPct).toBe(25)
    expect(placed?.widthPct).toBe(25)
    expect(placed?.clippedStart).toBe(false)
    expect(placed?.clippedEnd).toBe(false)
    expect(placed?.open).toBe(false)
  })

  it('a period that started before the window is clipped to its left edge', () => {
    const placed = placeSpan(period({ started_at: '2026-09-15T18:00:00Z' }), SINCE, UNTIL)
    expect(placed?.leftPct).toBe(0)
    expect(placed?.widthPct).toBe(50)
    expect(placed?.clippedStart).toBe(true)
  })

  it('a period that ended after the window is clipped to its right edge', () => {
    const placed = placeSpan(
      period({ started_at: '2026-09-16T18:00:00Z', ended_at: '2026-09-17T06:00:00Z' }),
      SINCE,
      UNTIL,
    )
    expect(placed?.leftPct).toBe(75)
    expect(placed?.widthPct).toBe(25)
    expect(placed?.clippedEnd).toBe(true)
  })

  it('a still-open period runs to the window\'s end and says so', () => {
    const placed = placeSpan(period({ started_at: '2026-09-16T18:00:00Z', ended_at: null }), SINCE, UNTIL)
    expect(placed?.leftPct).toBe(75)
    expect(placed?.widthPct).toBe(25)
    expect(placed?.open).toBe(true)
    expect(placed?.title).toContain('still open')
  })

  it('a period spanning the whole window fills the bar and is clipped at both edges', () => {
    const placed = placeSpan(
      period({ started_at: '2026-09-15T00:00:00Z', ended_at: '2026-09-18T00:00:00Z' }),
      SINCE,
      UNTIL,
    )
    expect(placed?.leftPct).toBe(0)
    expect(placed?.widthPct).toBe(100)
    expect(placed?.clippedStart).toBe(true)
    expect(placed?.clippedEnd).toBe(true)
  })

  it('a period entirely before the window is not drawn at all', () =>
    expect(
      placeSpan(period({ started_at: '2026-09-14T00:00:00Z', ended_at: '2026-09-15T00:00:00Z' }), SINCE, UNTIL),
    ).toBeNull())

  it('a period entirely after the window is not drawn either', () =>
    expect(
      placeSpan(period({ started_at: '2026-09-18T00:00:00Z', ended_at: '2026-09-19T00:00:00Z' }), SINCE, UNTIL),
    ).toBeNull())

  it('the tooltip names the state, both ends and a re-entry count', () => {
    const placed = placeSpan(period({ flap_count: 3 }), SINCE, UNTIL)
    expect(placed?.title).toBe('throttled · wed 16 sep 06:00 → 12:00 · re-entered 3 times')
  })

  it('a single visit says nothing about re-entry', () =>
    expect(placeSpan(period(), SINCE, UNTIL)?.title).not.toContain('re-entered'))
})

describe('tierFor -- which colour a state carries', () => {
  it('the critical states take the alarm tier', () => {
    expect(tierFor('token_conflict')).toBe('crit')
    expect(tierFor('silent')).toBe('crit')
    expect(tierFor('not_delivering')).toBe('crit')
    expect(tierFor('throttled')).toBe('crit')
  })

  it('a stalled rotation stays on the warning tier, as it does on the tile', () =>
    expect(tierFor('rotation_stalled')).toBe('warn'))

  it('unobserved is neutral -- never the alarm tier, never a healthy one', () => {
    expect(tierFor('unobserved')).toBe('unobs')
    expect(tierFor('unobserved')).not.toBe('crit')
    expect(tierFor('unobserved')).not.toBe('warn')
  })
})

describe('layoutLanes -- two states at once on one canary', () => {
  it('overlapping states stack, worst on top', () => {
    const lanes = layoutLanes(
      [
        period({ state: 'rotation_stalled', started_at: '2026-09-16T04:00:00Z', ended_at: '2026-09-16T14:00:00Z' }),
        period({ state: 'token_conflict', started_at: '2026-09-16T06:00:00Z', ended_at: '2026-09-16T12:00:00Z' }),
      ],
      SINCE,
      UNTIL,
    )
    expect(lanes).toHaveLength(2)
    expect(lanes[0][0].state).toBe('token_conflict')
    expect(lanes[1][0].state).toBe('rotation_stalled')
  })

  it('states that never overlap share one lane', () => {
    const lanes = layoutLanes(
      [
        period({ started_at: '2026-09-16T01:00:00Z', ended_at: '2026-09-16T02:00:00Z' }),
        period({ state: 'silent', started_at: '2026-09-16T10:00:00Z', ended_at: '2026-09-16T12:00:00Z' }),
      ],
      SINCE,
      UNTIL,
    )
    expect(lanes).toHaveLength(1)
  })

  it('a period outside the window takes no lane', () =>
    expect(layoutLanes([period({ started_at: '2026-09-01T00:00:00Z', ended_at: '2026-09-02T00:00:00Z' })], SINCE, UNTIL)).toEqual(
      [],
    ))
})

describe('historyRows -- one row per canary the window has something on', () => {
  const response: HistoryResponse = {
    range: '24h',
    since: SINCE,
    until: UNTIL,
    periods: [period(), period({ canary_id: 'canary-iot', canary_name: 'canary-iot', state: 'unobserved' })],
    summary: [entry(), entry({ canary_id: 'canary-iot', canary_name: 'canary-iot', state: 'unobserved', longest_s: 7200, total_s: 7200 })],
  }

  it('names each canary once, in the order the response gives them', () =>
    expect(historyRows(response).map((r) => r.name)).toEqual(['canary-srv', 'canary-iot']))

  it('writes each row\'s line from that canary\'s totals alone', () => {
    const rows = historyRows(response)
    expect(rows[0].summary).toBe('throttled once, 11 m')
    expect(rows[1].summary).toBe('birdcage was not watching for 2 h')
  })

  it('a canary with periods but no totals still reads "all quiet"', () => {
    const rows = historyRows({ ...response, summary: [] })
    expect(rows.every((r) => r.summary === 'all quiet')).toBe(true)
  })

  it('an empty fleet draws no rows -- the section says it in words instead', () =>
    expect(historyRows({ ...response, periods: [], summary: [] })).toEqual([]))
})

describe('historyTicks -- a few labels along the bar', () => {
  it('a quarter hour is labelled in clock minutes, every five', () => {
    const ticks = historyTicks('2026-09-17T08:45:00Z', '2026-09-17T09:00:00Z', '15m')
    expect(ticks.map((t) => t.label)).toEqual(['08:45', '08:50', '08:55', '09:00'])
  })

  it('an hour is labelled in clock minutes, every fifteen', () => {
    const ticks = historyTicks('2026-09-17T08:00:00Z', '2026-09-17T09:00:00Z', '1h')
    expect(ticks.map((t) => t.label)).toEqual(['08:00', '08:15', '08:30', '08:45', '09:00'])
  })

  it('a day is labelled in clock hours, every six', () => {
    const ticks = historyTicks(SINCE, UNTIL, '24h')
    expect(ticks.map((t) => t.label)).toEqual(['00:00', '06:00', '12:00', '18:00', '00:00'])
    expect(ticks[2].leftPct).toBe(50)
  })

  it('a fortnight is labelled in dates, every two days', () => {
    const ticks = historyTicks('2026-09-03T09:00:00Z', '2026-09-17T09:00:00Z', '14d')
    expect(ticks).toHaveLength(7)
    expect(ticks[0].label).toBe('fri 4 sep')
  })

  it('ninety days is labelled in dates, every fifteen', () =>
    expect(historyTicks('2026-06-19T09:00:00Z', '2026-09-17T09:00:00Z', '90d')).toHaveLength(6))
})

describe('historyRangeLabel -- the section heading, in the picker\'s own words', () => {
  it('matches the range chip exactly, for every range the dashboard offers', () => {
    expect(historyRangeLabel('15m')).toBe('15 m')
    expect(historyRangeLabel('1h')).toBe('1 h')
    expect(historyRangeLabel('24h')).toBe('24 h')
    expect(historyRangeLabel('14d')).toBe('14 d')
    expect(historyRangeLabel('90d')).toBe('90 d')
  })
})
