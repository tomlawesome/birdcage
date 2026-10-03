// ADR-0012 decision 9 (issue #116): the closed vocabulary a scan run's
// stage moves through, forward only, and the human words for each --
// shared by the pending tile sentence, the self-test-failed sentence and
// the canary page's stage timeline, so the three never drift apart on
// what a stage is called.
import type { RunStage } from '../types'

/** The stages in order, exactly as ADR-0012 decision 9's table lists
 * them. */
export const STAGE_ORDER: RunStage[] = ['ordered', 'collected', 'mounts_checked', 'db_refreshed', 'scanning', 'answered']

const STAGE_LABELS: Record<RunStage, string> = {
  ordered: 'order sent',
  collected: 'order received',
  mounts_checked: 'mounts checked',
  db_refreshed: 'vulnerability list refreshed',
  scanning: 'scanning',
  answered: 'result received',
}

/** The human label for one stage -- falls back to the raw string for a
 * stage this build does not know, so a newer server never renders blank. */
export function stageLabel(stage: RunStage): string {
  return STAGE_LABELS[stage] ?? stage
}

export function stageIndex(stage: RunStage): number {
  return STAGE_ORDER.indexOf(stage)
}
