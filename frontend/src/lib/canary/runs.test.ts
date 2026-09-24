// ADR-0012 decision 11 (issue #116): the Runs list and the stage
// timeline's own data decisions -- ordering, verdict colour, and the
// forward-only done/current/pending split.
import { describe, expect, it } from 'vitest'
import { runRows, stageTimeline } from './runs'
import type { RunsResponse } from '../types'

const now = '2026-09-05T22:04:31Z'

describe('runRows', () => {
  it('no runs response: empty list', () => {
    expect(runRows(null, now)).toEqual([])
  })

  it('a passed proof run: verdict, last stage and reason, never a run id', () => {
    const runs: RunsResponse = {
      runs: [
        {
          trigger: 'proof',
          issued_at: '2026-09-05T21:30:00Z',
          ended_at: '2026-09-05T21:32:00Z',
          verdict: 'pass',
          last_stage: 'answered',
          reason: '',
          snapshot_id: 'snap-1',
        },
      ],
    }
    const rows = runRows(runs, now)
    expect(rows).toHaveLength(1)
    expect(rows[0].trigger).toBe('proof')
    expect(rows[0].verdict).toBe('pass')
    expect(rows[0].verdictCls).toBe('ok')
    expect(rows[0].lastStage).toBe('result received')
    expect(rows[0].ended).not.toBe('still open')
    expect(Object.keys(rows[0])).not.toContain('run_id')
    expect(JSON.stringify(rows[0])).not.toContain('run_id')
  })

  it('a failed manual run: reason carried, al colour', () => {
    const runs: RunsResponse = {
      runs: [
        {
          trigger: 'manual',
          issued_at: '2026-09-05T21:00:00Z',
          ended_at: '2026-09-05T21:01:00Z',
          verdict: 'fail',
          last_stage: 'scanning',
          reason: 'masked_paths incomplete',
          snapshot_id: 'snap-2',
        },
      ],
    }
    const rows = runRows(runs, now)
    expect(rows[0].verdictCls).toBe('al')
    expect(rows[0].reason).toBe('masked_paths incomplete')
  })

  it('an expired run still open: "still open" and wn colour', () => {
    const runs: RunsResponse = {
      runs: [
        {
          trigger: 'proof',
          issued_at: '2026-09-05T21:00:00Z',
          ended_at: null,
          verdict: null,
          last_stage: 'collected',
          reason: '',
          snapshot_id: null,
        },
      ],
    }
    const rows = runRows(runs, now)
    expect(rows[0].ended).toBe('still open')
    expect(rows[0].verdict).toBe('open')
    expect(rows[0].verdictCls).toBe('')
  })
})

describe('stageTimeline', () => {
  it('no open run: empty timeline', () => {
    expect(stageTimeline(undefined)).toEqual([])
    expect(stageTimeline(null)).toEqual([])
  })

  it('an open run at mounts_checked: earlier stages done, this one current, later pending', () => {
    const steps = stageTimeline('mounts_checked')
    expect(steps.map((s) => s.state)).toEqual(['done', 'done', 'current', 'pending', 'pending', 'pending'])
    expect(steps.map((s) => s.stage)).toEqual(['ordered', 'collected', 'mounts_checked', 'db_refreshed', 'scanning', 'answered'])
    expect(steps[2].label).toBe('mounts checked')
  })

  it('an open run at ordered: nothing done yet', () => {
    const steps = stageTimeline('ordered')
    expect(steps[0].state).toBe('current')
    expect(steps.slice(1).every((s) => s.state === 'pending')).toBe(true)
  })
})
