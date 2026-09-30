// What one canary's page reads out of the responses App.svelte already
// has, worked out as plain data (issue #118). The page's four blocks --
// the line, the self-test ledger, the history thread and the facts
// column -- all narrow the same few responses to this canary, so the
// narrowing lives here once rather than four times in the component.
import type {
  Canary,
  CanaryPageResponse,
  HistoryPeriod,
  HistoryResponse,
  SelfTestRunSummary,
  SelfTestServiceResult,
  TraceCanary,
  TraceResponse,
  Visitor,
} from '../types'
import { portForService } from '../sentence/ports'

/** Everything the page is drawn from: its own read (issue #118's
 * /api/canary) plus the dashboard reads App.svelte already holds, none
 * of which are re-fetched for this page. */
export interface CanaryPageInput {
  page: CanaryPageResponse
  trace: TraceResponse
  visitors: Visitor[]
  history: HistoryResponse | null
}

export function canaryOf(input: CanaryPageInput): Canary {
  return input.page.canary
}

/** This canary's row of the trace -- its heartbeats and its hits. Null
 * when the trace does not carry it, which a canary enrolled since the
 * last trace read can legitimately be. */
export function traceOf(input: CanaryPageInput): TraceCanary | null {
  return input.trace.canaries.find((c) => c.id === input.page.canary.id) ?? null
}

/** The visitors that reached this canary, newest last_at first. A
 * visitor is a fleet-wide grouping, so one that walked four canaries
 * appears on each of their pages -- which is the point: "the same
 * address that walked all four canaries tonight". */
export function visitorsHere(input: CanaryPageInput): Visitor[] {
  const id = input.page.canary.id
  return input.visitors
    .filter((v) => v.canaries.some((c) => c.id === id))
    .sort((a, b) => Date.parse(b.last_at) - Date.parse(a.last_at))
}

/** Every state period recorded for this canary in the window, newest
 * start first. */
export function periodsHere(input: CanaryPageInput): HistoryPeriod[] {
  const id = input.page.canary.id
  return (input.history?.periods ?? [])
    .filter((p) => p.canary_id === id)
    .sort((a, b) => Date.parse(b.started_at) - Date.parse(a.started_at))
}

export interface Silence {
  startedAt: string
  endedAt: string | null
  /** How long it lasted, in seconds -- measured to `now` while open. */
  seconds: number
  open: boolean
}

/** The canary's silences in the window, newest first: the marks the line
 * draws as hollow ink circles, and the clauses the sentence counts. */
export function silences(input: CanaryPageInput): Silence[] {
  const now = Date.parse(input.trace.now)
  return periodsHere(input)
    .filter((p) => p.state === 'silent')
    .map((p) => {
      const started = Date.parse(p.started_at)
      const ended = p.ended_at === null ? null : Date.parse(p.ended_at)
      return {
        startedAt: p.started_at,
        endedAt: p.ended_at,
        seconds: Math.max(0, ((ended ?? now) - started) / 1000),
        open: ended === null,
      }
    })
}

/** How a service came out of the last completed self-test run. 'passed'
 * and 'failed' are the run's own verdict; 'untested' is a service the
 * canary lists a port for that the run carried no target for at all --
 * ADR-0004 rule 3's third card, and not a fault. */
export type SelfTestOutcome = 'passed' | 'failed' | 'untested'

export interface SelfTestCard {
  service: string
  /** The listening port, absent for a lure with no port of its own
   * (portscan is the agent's own detector, not a module on a port). */
  port: string | null
  outcome: SelfTestOutcome
  grade: SelfTestServiceResult['grade'] | null
  /** The service is probed but is not a door anyone can knock on -- it
   * has no entry in the canary's listening ports. */
  lure: boolean
}

/** Splits the canary's ports display string into its service names, in
 * the order the tile already shows them. */
export function listeningServices(ports: string): string[] {
  return ports
    .split(' · ')
    .map((part) => part.trim().split(/\s+/)[0])
    .filter((name) => name !== '')
}

/** The ledger's cards, in the order the strip draws them: the services
 * this canary listens on first, in the tile's own order -- those are the
 * doors a visitor can knock on -- then the lures the self-test also
 * probes. A listening service the run never probed comes last within its
 * group as an untested card.
 *
 * Returns an empty list when no run has ever completed: there is no
 * ledger to draw, which the heading says in words instead. */
export function selfTestCards(canary: Canary): SelfTestCard[] {
  const results = canary.self_test ?? []
  if (results.length === 0) return []
  const byService = new Map(results.map((r) => [r.service, r]))
  const listening = listeningServices(canary.ports)

  const cards: SelfTestCard[] = listening.map((service) => {
    const result = byService.get(service)
    return {
      service,
      port: portForService(canary.ports, service),
      outcome: result === undefined ? 'untested' : result.passed ? 'passed' : 'failed',
      grade: result?.grade ?? null,
      lure: false,
    }
  })
  for (const result of results) {
    if (listening.includes(result.service)) continue
    cards.push({
      service: result.service,
      port: portForService(canary.ports, result.service),
      outcome: result.passed ? 'passed' : 'failed',
      grade: result.grade,
      lure: true,
    })
  }
  return cards
}

/** The run the ledger reports: the newest completed one. Null when none
 * has ever completed. */
export function lastCompletedRun(runs: SelfTestRunSummary[]): SelfTestRunSummary | null {
  return runs.find((r) => r.completed_at !== undefined && r.completed_at !== null) ?? null
}
