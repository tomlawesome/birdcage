// ADR-0012 decision 11 (issue #116): a scanner canary page's own Runs
// list (trigger, issued, ended, verdict, last stage, reason) and its
// open run's stage timeline -- worked out as plain data, the same split
// lib/canary/thread.ts already uses for the state history. Never reads
// or carries a run id (decision 9's own rule).
import type { RunRecord, RunStage, RunsResponse } from '../types'
import { formatClockShort, relativeDayLabel } from '../sentence/time'
import { STAGE_ORDER, stageIndex, stageLabel } from '../sentence/stage'

/** "today 14:02" / "thu 3 sep 07:12" -- the Runs list's own timestamp,
 * the thread's own whenLabel shape (canary/thread.ts), duplicated
 * rather than shared: that helper is module-private there. */
function whenLabel(iso: string, now: string): string {
  const day = relativeDayLabel(iso, now)
  return `${day} ${formatClockShort(iso)}`
}

export interface RunRow {
  key: string
  trigger: string
  issued: string
  ended: string
  verdict: string
  verdictCls: string
  lastStage: string
  reason: string
  snapshotId: string | null
}

/** One row per run, in the order the API already sends (newest first) --
 * this does not re-sort, so a test fixture's own order is what renders. */
export function runRows(runs: RunsResponse | null, now: string): RunRow[] {
  if (!runs) return []
  return runs.runs.map((r, i) => runRow(r, now, i))
}

function runRow(r: RunRecord, now: string, i: number): RunRow {
  return {
    key: `${r.issued_at}:${i}`,
    trigger: r.trigger === 'manual' ? 'manual' : 'proof',
    issued: whenLabel(r.issued_at, now),
    ended: r.ended_at ? whenLabel(r.ended_at, now) : 'still open',
    verdict: r.verdict ?? 'open',
    verdictCls: verdictClass(r.verdict),
    lastStage: stageLabel(r.last_stage),
    reason: r.reason,
    snapshotId: r.snapshot_id,
  }
}

function verdictClass(verdict: RunRecord['verdict']): string {
  if (verdict === 'pass') return 'ok'
  if (verdict === 'fail') return 'al'
  if (verdict === 'expired') return 'wn'
  return ''
}

export interface StageStep {
  stage: RunStage
  label: string
  /** 'done' is behind the current stage, 'current' is where the run sits
   * now, 'pending' is ahead of it -- forward-only, matching decision 9's
   * own rule that a stage never moves backward. */
  state: 'done' | 'current' | 'pending'
}

/** The six-stage timeline for an open run, the current stage marked --
 * empty when there is no open run to draw one for. */
export function stageTimeline(currentStage: RunStage | null | undefined): StageStep[] {
  if (!currentStage) return []
  const idx = stageIndex(currentStage)
  return STAGE_ORDER.map((stage, i) => ({
    stage,
    label: stageLabel(stage),
    state: i < idx ? 'done' : i === idx ? 'current' : 'pending',
  }))
}
