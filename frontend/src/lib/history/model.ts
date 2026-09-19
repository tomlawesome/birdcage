// Issue #56: everything History.svelte draws, worked out as plain data --
// which window a range chip asks for, where a period sits on the bar,
// which lane it stacks in, what colour tier it carries, and the one line
// of English beside it. The component only positions what this returns,
// the same split lib/band and lib/sentence already use.
//
// All arithmetic is in milliseconds off Date.parse and all positions are
// percentages of the window, so the bar is resolution-independent and
// the sums are testable without a DOM.
import type { HistoryPeriod, HistoryRange, HistoryResponse, HistoryState, HistorySummary, Range } from '../types'
import { durationCoarse, durationExact } from '../sentence/duration'
import { formatClock, formatDate } from '../band/format'

/** The dashboard's five range chips against the endpoint's three windows
 * (issue #56): each chip asks for the nearest window it can get. 15 m and
 * 1 h have no shorter history to ask for, and a fortnight is nearer a
 * week than a month, so the chip and the section can disagree about how
 * far back they look -- the section's heading says which window it drew. */
const HISTORY_RANGE: Record<Range, HistoryRange> = {
  '15m': '24h',
  '1h': '24h',
  '24h': '24h',
  '14d': '7d',
  '90d': '30d',
}

export function historyRangeFor(range: Range): HistoryRange {
  return HISTORY_RANGE[range]
}

const HISTORY_RANGE_LABEL: Record<HistoryRange, string> = {
  '24h': '24 hours',
  '7d': '7 days',
  '30d': '30 days',
}

/** "7 days" -- the section heading's window, in the events heading's voice
 * ("events · 14 days · none"). */
export function historyRangeLabel(range: HistoryRange): string {
  return HISTORY_RANGE_LABEL[range]
}

/** The three colour tiers a span can carry. 'crit' is the existing alarm
 * colour, 'warn' the existing --repeat warning; 'unobs' is neither --
 * birdcage not watching is not the canary's fault, so it never takes the
 * alarm colour, and it is not health either, so it never takes ok green. */
export type HistoryTier = 'crit' | 'warn' | 'unobs'

const TIER: Record<HistoryState, HistoryTier> = {
  token_conflict: 'crit',
  silent: 'crit',
  not_delivering: 'crit',
  throttled: 'crit',
  rotation_stalled: 'warn',
  unobserved: 'unobs',
}

export function tierFor(state: HistoryState): HistoryTier {
  return TIER[state]
}

/** Worst first, the same order types.ts gives CanaryStatus, with the
 * neutral 'unobserved' last. Decides which span sits in the top lane and
 * which clause opens a summary line. */
const STATE_ORDER: HistoryState[] = [
  'token_conflict',
  'silent',
  'not_delivering',
  'throttled',
  'rotation_stalled',
  'unobserved',
]

function stateRank(state: HistoryState): number {
  return STATE_ORDER.indexOf(state)
}

const STATE_LABEL: Record<HistoryState, string> = {
  token_conflict: 'token conflict',
  silent: 'silent',
  not_delivering: 'not delivering',
  throttled: 'throttled',
  rotation_stalled: 'rotation stalled',
  unobserved: 'birdcage was not watching',
}

/** The window at a glance: seconds only where they are all there is, the
 * remainder kept where there is one ("3 h 20 m", never "3 h"), and
 * dropped where there is none ("2 h", never "2 h 0 m"). durationExact's
 * "11 m 0 s" is the tile's exact voice, not this line's. */
export function spanDuration(seconds: number): string {
  if (seconds < 60) return durationExact(seconds)
  if (seconds < 3600) return durationCoarse(seconds)
  const exact = durationExact(seconds)
  return exact.endsWith(' 0 m') || exact.endsWith(' 0 h') ? durationCoarse(seconds) : exact
}

/** "once" / "twice" / "4 times" -- a count of spans, so digits from three
 * up, the same rule the tiles' compact labels follow. */
function timesPhrase(count: number): string {
  if (count === 1) return 'once'
  if (count === 2) return 'twice'
  return `${count} times`
}

/** One row's line of English, written from the window's totals:
 *   "throttled 4 times, longest 11 m"
 *   "silent once, 3 h 20 m"
 *   "birdcage was not watching for 2 h"   (nothing but unobserved)
 *   "all quiet"                           (nothing at all)
 * Several states on one canary read worst first, joined by the
 * dashboard's " · ", with the unobserved clause always last: it says
 * what birdcage missed, not what the canary did. */
export function summaryLine(entries: HistorySummary[]): string {
  if (entries.length === 0) return 'all quiet'
  const ordered = [...entries].sort((a, b) => stateRank(a.state) - stateRank(b.state))
  const clauses = ordered.map((entry) => {
    if (entry.state === 'unobserved') return `${STATE_LABEL.unobserved} for ${spanDuration(entry.total_s)}`
    if (entry.count === 1) return `${STATE_LABEL[entry.state]} once, ${spanDuration(entry.longest_s)}`
    return `${STATE_LABEL[entry.state]} ${timesPhrase(entry.count)}, longest ${spanDuration(entry.longest_s)}`
  })
  return clauses.join(' · ')
}

export interface PlacedSpan {
  key: string
  state: HistoryState
  tier: HistoryTier
  /** Percentages of the window, left edge and width. */
  leftPct: number
  widthPct: number
  /** The period began before the window and is drawn from its left edge. */
  clippedStart: boolean
  /** The period ended after the window (only possible if the API sends
   * one; an open period is `open`, not `clippedEnd`). */
  clippedEnd: boolean
  /** Still running -- drawn to the window's right edge. */
  open: boolean
  /** The hover/focus tooltip. */
  title: string
}

function stamp(ms: number): string {
  const d = new Date(ms)
  return `${formatDate(d)} ${formatClock(d)}`
}

/** "throttled · fri 4 sep 22:15 → 22:24 · re-entered 3 times". The date
 * is dropped from the end when it is the same day, the way the band's
 * event time already drops it. Always the period's own times, never the
 * clipped ones: a span that started before the window should say so by
 * naming the real start. */
function spanTitle(period: HistoryPeriod, startMs: number, endMs: number | null): string {
  const ends =
    endMs === null
      ? 'still open'
      : new Date(startMs).getUTCDate() === new Date(endMs).getUTCDate()
        ? formatClock(new Date(endMs))
        : stamp(endMs)
  const flaps = period.flap_count > 1 ? ` · re-entered ${period.flap_count} times` : ''
  return `${STATE_LABEL[period.state]} · ${stamp(startMs)} → ${ends}${flaps}`
}

function round(n: number): number {
  return Math.round(n * 1000) / 1000
}

/** Where one period sits on a since→until bar, as percentages, clipped to
 * the window at both edges. null when it falls outside the window
 * entirely -- the API may send a period the window only touches, and a
 * span with nothing inside is not drawn. An open period (ended_at null)
 * runs to `until`. */
export function placeSpan(period: HistoryPeriod, since: string, until: string): PlacedSpan | null {
  const sinceMs = Date.parse(since)
  const untilMs = Date.parse(until)
  const span = untilMs - sinceMs
  if (!(span > 0)) return null

  const startMs = Date.parse(period.started_at)
  const endedMs = period.ended_at === null ? null : Date.parse(period.ended_at)
  const endMs = endedMs ?? untilMs
  if (Number.isNaN(startMs) || Number.isNaN(endMs)) return null

  const from = Math.max(startMs, sinceMs)
  const to = Math.min(endMs, untilMs)
  if (to < from || from >= untilMs || to <= sinceMs) return null

  return {
    key: `${period.canary_id}:${period.state}:${period.started_at}`,
    state: period.state,
    tier: tierFor(period.state),
    leftPct: round(((from - sinceMs) / span) * 100),
    widthPct: round(((to - from) / span) * 100),
    clippedStart: startMs < sinceMs,
    clippedEnd: endedMs !== null && endedMs > untilMs,
    open: endedMs === null,
    title: spanTitle(period, startMs, endedMs),
  }
}

function overlaps(a: PlacedSpan, b: PlacedSpan): boolean {
  return a.leftPct < b.leftPct + b.widthPct && b.leftPct < a.leftPct + a.widthPct
}

/** Two states at once on one canary stack as lanes in the same bar rather
 * than one hiding the other: worst first, so lane 0 -- drawn at the top --
 * always carries the loudest thing that was true at that moment. A span
 * takes the first lane it does not collide in, so a quiet fleet still
 * draws a single-lane bar. */
export function layoutLanes(periods: HistoryPeriod[], since: string, until: string): PlacedSpan[][] {
  const placed = periods
    .map((p) => ({ period: p, span: placeSpan(p, since, until) }))
    .filter((x): x is { period: HistoryPeriod; span: PlacedSpan } => x.span !== null)
    .sort(
      (a, b) =>
        stateRank(a.period.state) - stateRank(b.period.state) ||
        Date.parse(a.period.started_at) - Date.parse(b.period.started_at),
    )
    .map((x) => x.span)

  const lanes: PlacedSpan[][] = []
  for (const span of placed) {
    const lane = lanes.find((existing) => !existing.some((other) => overlaps(span, other)))
    if (lane) lane.push(span)
    else lanes.push([span])
  }
  return lanes
}

export interface HistoryRow {
  canaryId: string
  name: string
  lanes: PlacedSpan[][]
  summary: string
}

/** One row per canary the window has something to say about, in the
 * order the response names them. A fleet with nothing recorded returns
 * no rows at all, which the section says in words instead. */
export function historyRows(history: HistoryResponse): HistoryRow[] {
  const names = new Map<string, string>()
  for (const entry of history.summary) if (!names.has(entry.canary_id)) names.set(entry.canary_id, entry.canary_name)
  for (const period of history.periods) if (!names.has(period.canary_id)) names.set(period.canary_id, period.canary_name)

  return [...names].map(([canaryId, name]) => ({
    canaryId,
    name,
    lanes: layoutLanes(
      history.periods.filter((p) => p.canary_id === canaryId),
      history.since,
      history.until,
    ),
    summary: summaryLine(history.summary.filter((s) => s.canary_id === canaryId)),
  }))
}

export interface HistoryTick {
  leftPct: number
  label: string
}

const TICK_STEP_S: Record<HistoryRange, number> = {
  '24h': 6 * 3600,
  '7d': 86400,
  '30d': 5 * 86400,
}

/** A few labels along the bar, on round boundaries: clock hours every six
 * for a day, dates for a week or a month. Ticks outside the window are
 * dropped rather than clamped -- a label pinned to an edge it does not
 * belong to would misread the bar. */
export function historyTicks(since: string, until: string, range: HistoryRange): HistoryTick[] {
  const sinceMs = Date.parse(since)
  const untilMs = Date.parse(until)
  const span = untilMs - sinceMs
  if (!(span > 0)) return []

  const stepMs = TICK_STEP_S[range] * 1000
  const ticks: HistoryTick[] = []
  for (let at = Math.ceil(sinceMs / stepMs) * stepMs; at <= untilMs; at += stepMs) {
    const d = new Date(at)
    ticks.push({
      leftPct: round(((at - sinceMs) / span) * 100),
      label: range === '24h' ? formatClock(d) : formatDate(d),
    })
  }
  return ticks
}
