// One canary's line, at its own scale (issue #118, ADR-0004's
// "Extension: the canary page"). The same axis, the same segments, the
// same placement loop and the same bump maths the band already uses --
// imported, never copied: what differs is that there is one line instead
// of four, so a rise has room to climb to 60px, and the line carries two
// marks the band has no room for: the fortnight's earlier silences, and
// a tick under the line per self-test run.
import type { Canary, SelfTestRunSummary, TraceCanary, TraceHit, VisitorKind } from '../types'
import { axisCaptions, axisTicks, dayTicks, nowLabel, type AxisTick, type Caption, type DayTick } from './axis'
import { beatAgos } from './beats'
import { buildLine2, formatClockWithSeconds, formatDuration, joinTried, isHighSignalRise } from './format'
import { cx, segmentsForRange, type Seg } from './segments'
import { placeRises, type PlacedBump, type PlacedLabel, type Rise } from './placement'
import type { Silence } from '../canary/model'

/** The line's y, in the page's own coordinates -- gen.py round 7's
 * Y = 300, ten below the band's first line, because nothing is stacked
 * under it. */
export const LINE_Y = 300

/** What a rise on this page starts at. A sweep is the loudest thing a
 * canary can report, and at this scale it takes the ADR's full 60px;
 * every other kind starts at 44 and the placement loop grows it from
 * there if the words do not fit. */
const RISE_H: Record<VisitorKind, number> = { sweep: 60, repeat: 44, inside: 44, touch: 44 }
const RIPPLE_H = 22
const RIPPLE_BW = 12

const LANE_VAR: Record<string, string> = {
  lan: 'var(--lan)',
  srv: 'var(--srv)',
  iot: 'var(--iot)',
  guest: 'var(--guest)',
}

export interface SilenceMark {
  x: number
  labelX: number
  labelY: number
  /** Empty when a labelled rise is on the line: the silence labels and a
   * rise's own two lines hang in the same band above it, and a night
   * with a sweep on it has no room for both. The mark itself always
   * stays -- the silence happened whatever else did. */
  text: string
}

export interface SelfTestTick {
  x: number
  failed: boolean
}

export interface FailedRunLabel {
  x: number
  /** The stem runs from just under the filled tick up to here. */
  stemTop: number
  y1: number
  y2: number
  lead: string
  failed: string
  detail: string
}

export interface CanaryLineModel {
  x0: number
  x1: number
  y: number
  segs: Seg[]
  color: string
  name: string
  /** Where the solid line stops: x1 normally, the last heartbeat when
   * the canary is silent. */
  xTo: number
  drop: { xs: number; yd: number; curveD: string; sentence: string } | null
  beatMarks: number[]
  silenceMarks: SilenceMark[]
  selfTestTicks: SelfTestTick[]
  failedRun: FailedRunLabel | null
  bumps: PlacedBump[]
  labels: PlacedLabel[]
  axisTicks: AxisTick[]
  dayTicks: DayTick[]
  captions: Caption[]
  now: { x: number; text: string }
  axisY: number
  brink: { x: number; yTop: number; yBottom: number }
  bottom: number
}

export interface CanaryLineInput {
  canary: Canary
  trace: TraceCanary | null
  now: string
  range: Parameters<typeof segmentsForRange>[0]
  runs: SelfTestRunSummary[]
  /** Newest first, as lib/canary/model's silences() returns them. */
  silences: Silence[]
}

const WEEKDAYS = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat']
const MONTHS = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec']

function dateLower(ms: number): string {
  const d = new Date(ms)
  return `${WEEKDAYS[d.getUTCDay()]} ${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]}`
}

/** "11 min" -- the silence mark's own compact label, minutes only
 * (a silence marked on the line is never sub-minute: a canary is not
 * called silent until it has missed beats). */
function silenceMinutes(seconds: number): string {
  return `${Math.max(1, Math.round(seconds / 60))} min`
}

/** Groups a canary's hits into the same visitor+kind families the band
 * builds, and clusters each family's x positions -- the identical rule,
 * reached through the same helpers, so a rise means the same thing on
 * both pages. */
function risesFor(
  hits: TraceHit[],
  y: number,
  canaryId: string,
  now: Date,
  cxFn: (ago: number) => number,
): Rise[] {
  const agoOf = (iso: string) => (now.getTime() - Date.parse(iso)) / 1000
  const groups = new Map<string, TraceHit[]>()
  for (const hit of hits) {
    const key = `${hit.visitor} ${hit.kind}`
    const list = groups.get(key)
    if (list) list.push(hit)
    else groups.set(key, [hit])
  }

  const rises: Rise[] = []
  for (const family of groups.values()) {
    const withX = family.map((hit, index) => ({ hit, index, x: cxFn(agoOf(hit.at)) })).sort((a, b) => a.x - b.x)
    const clusters: Array<{ xFrom: number; xTo: number; items: typeof withX }> = []
    for (const item of withX) {
      const last = clusters[clusters.length - 1]
      if (last && item.x - last.xTo <= 6) {
        last.xTo = item.x
        last.items.push(item)
      } else {
        clusters.push({ xFrom: item.x, xTo: item.x, items: [item] })
      }
    }
    let widest = 0
    for (let i = 1; i < clusters.length; i++) {
      const a = clusters[i]
      const b = clusters[widest]
      const wa = a.xTo - a.xFrom
      const wb = b.xTo - b.xFrom
      if (wa > wb || (wa === wb && a.items.length > b.items.length)) widest = i
    }
    clusters.forEach((cluster, index) => {
      const ordered = [...cluster.items].sort((a, b) => a.index - b.index).map((i) => i.hit)
      const kind = ordered[0].kind
      // Same rule as the band (#59): the group's representative rise keeps
      // its label only when it is a credential attempt or a poisoner answer.
      const labelled = index === widest && isHighSignalRise(ordered)
      let l1 = ''
      let l2 = ''
      if (labelled) {
        l1 = joinTried(ordered.map((h) => h.tried))
        const newest = ordered.reduce((a, b) => (Date.parse(b.at) > Date.parse(a.at) ? b : a))
        l2 = buildLine2(newest.visitor, canaryId, newest.service, new Date(newest.at), now)
      }
      rises.push({ xFrom: cluster.xFrom, xTo: cluster.xTo, y, kind, l1, l2, labelled, h: RISE_H[kind] })
    })
  }
  return rises
}

export function buildCanaryLineModel(input: CanaryLineInput, containerWidth: number): CanaryLineModel {
  const { canary } = input
  const x0 = 190
  const x1 = containerWidth - 80
  const y = LINE_Y
  const now = new Date(input.now)
  const segs = segmentsForRange(input.range)
  const cxFn = (ago: number) => cx(ago, segs, x0, x1)
  const agoOf = (iso: string) => (now.getTime() - Date.parse(iso)) / 1000
  const color = LANE_VAR[canary.lane] ?? 'var(--ink-2)'

  let xTo = x1
  let drop: CanaryLineModel['drop'] = null
  let sinceAgo = 0
  if (canary.status === 'silent' && canary.last_heartbeat_at) {
    sinceAgo = agoOf(canary.last_heartbeat_at)
    const xs = cxFn(sinceAgo)
    const yd = y + 22
    xTo = xs
    drop = {
      xs,
      yd,
      curveD: `M${xs.toFixed(1)},${y} C${(xs + 10).toFixed(1)},${y} ${(xs + 8).toFixed(1)},${yd} ${(xs + 20).toFixed(1)},${yd}`,
      sentence: `dropped out · last heartbeat ${formatClockWithSeconds(new Date(canary.last_heartbeat_at))} · silent ${formatDuration(sinceAgo)}`,
    }
  }

  const beatMarks = beatAgos(input.trace?.beats ?? [], now, sinceAgo).map(cxFn)

  // The earlier silences, oldest first so the oldest label sits highest:
  // the labels hang to the left of their marks on their own rows, which
  // is what keeps them clear of a failed self-test's stem to the right.
  const earlier = input.silences.filter((s) => !s.open).slice().reverse()

  const selfTestTicks: SelfTestTick[] = []
  let failedRun: FailedRunLabel | null = null
  for (const run of input.runs) {
    const x = cxFn(agoOf(run.issued_at))
    const failed = run.passed === false
    selfTestTicks.push({ x, failed })
    // Only the newest failed run is spelled out: the words belong to the
    // run still being asked about, and a fortnight of them would be a
    // wall of text over the line.
    if (failed && failedRun === null) {
      failedRun = {
        x,
        stemTop: y - 34,
        y1: y - 52,
        y2: y - 40,
        lead: `self-test ${new Date(run.issued_at).toISOString().slice(11, 16)} · `,
        failed: failedRunFailedWords(run),
        detail: failedRunDetail(input, run),
      }
    }
  }

  const rises = input.trace ? risesFor(input.trace.hits, y, canary.id, now, cxFn) : []
  const layout = placeRises(rises, x0, x1, y, { rippleH: RIPPLE_H, rippleBw: RIPPLE_BW })
  const axisY = y + 42

  const labelSilences = layout.labels.length === 0
  const silenceMarks: SilenceMark[] = earlier.map((silence, i) => {
    const x = cxFn(agoOf(silence.startedAt))
    return {
      x,
      labelX: x - 8,
      labelY: y - 12 - 14 * (earlier.length - 1 - i),
      text: labelSilences ? `${dateLower(Date.parse(silence.startedAt))} · silent ${silenceMinutes(silence.seconds)}` : '',
    }
  })

  return {
    x0,
    x1,
    y,
    segs,
    color,
    name: canary.name,
    xTo,
    drop,
    beatMarks,
    silenceMarks,
    selfTestTicks,
    failedRun,
    bumps: layout.bumps,
    labels: layout.labels,
    axisTicks: axisTicks(segs, x0, x1),
    dayTicks: dayTicks(now, segs, x0, x1),
    captions: axisCaptions(segs, x0, x1),
    now: nowLabel(now, x1),
    axisY,
    brink: { x: x1, yTop: y - 110, yBottom: y + 40 },
    bottom: axisY + 32,
  }
}

/** "telnet did not answer" -- the bold half of the failed run's label. */
function failedRunFailedWords(run: SelfTestRunSummary): string {
  const names = (run.failed_services ?? []).map((s) => s.split(/\s+/)[0])
  if (names.length === 0) return 'a service did not answer'
  if (names.length === 1) return `${names[0]} did not answer`
  return `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]} did not answer`
}

/** "ssh, smb, portscan answered · next run 04:00 tomorrow" -- the dim
 * second line: what the same run did reach, and when the next one is. */
function failedRunDetail(input: CanaryLineInput, run: SelfTestRunSummary): string {
  const failedServices = new Set((run.failed_services ?? []).map((s) => s.split(/\s+/)[0]))
  const answered = (input.canary.self_test ?? [])
    .filter((r) => !failedServices.has(r.service))
    .map((r) => r.service)
  const head = answered.length > 0 ? `${answered.join(', ')} answered` : 'nothing else answered'
  const schedule = scheduleOf(run)
  return schedule ? `${head} · next run ${schedule}` : head
}

/** The next scheduled run, said from the run's own time of day: a daily
 * self-test's next run is the same clock time tomorrow. */
function scheduleOf(run: SelfTestRunSummary): string | null {
  const at = new Date(run.issued_at)
  if (Number.isNaN(at.getTime())) return null
  return `${at.toISOString().slice(11, 16)} tomorrow`
}
