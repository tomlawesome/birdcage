// Builds the full render model for one trace response: groups each
// canary's hits into rises (a visitor+kind on one canary line), clusters
// them the way gen.py's trace() does, runs the placement loop, and adds
// the band lines, beat marks, the silent-canary drop, the axis and the
// brink line. Band.svelte only turns this into SVG elements.
import type { Lane, Range, TraceCanary, TraceHit, TraceResponse, VisitorKind } from '../types'
import { axisCaptions, axisTicks, dayTicks, nowLabel, type AxisTick, type Caption, type DayTick } from './axis'
import { beatAgos } from './beats'
import { formatClockWithSeconds, formatDuration, buildLine2, joinTried, isHighSignalRise } from './format'
import { cx, segmentsForRange, type Seg } from './segments'
import { placeRises, type Box, type PlacedBump, type PlacedLabel, type Rise } from './placement'

export const LANE_ORDER: Lane[] = ['lan', 'srv', 'iot', 'guest']
export const PITCH = 12
export const BAND_TOP = 290

const LANE_VAR: Record<Lane, string> = {
  lan: 'var(--lan)',
  srv: 'var(--srv)',
  iot: 'var(--iot)',
  guest: 'var(--guest)',
}

const KIND_VAR: Record<VisitorKind, string> = {
  sweep: 'var(--sweep)',
  repeat: 'var(--repeat)',
  inside: 'var(--inside)',
  touch: 'var(--touch)',
}

export interface BandLine {
  canaryId: string
  lane: Lane
  y: number
  color: string
  /** For an ok line the solid stroke runs the full X0..X1; for a silent one it stops at xTo (the last heartbeat). */
  xTo: number
}

export interface SilentDrop {
  canaryId: string
  y: number
  yd: number
  xs: number
  curveD: string
  color: string
  sentence: string
}

export interface BeatMark {
  x: number
  y: number
}

export interface BandLabel {
  x: number
  y: number
  text: string
  color: string
}

export interface BandModel {
  x0: number
  x1: number
  segs: Seg[]
  bandY: number[]
  lines: BandLine[]
  silentDrops: SilentDrop[]
  beatMarks: BeatMark[]
  bandLabels: BandLabel[]
  bumps: PlacedBump[]
  labels: PlacedLabel[]
  axisTicks: AxisTick[]
  dayTicks: DayTick[]
  captions: Caption[]
  now: { x: number; text: string }
  axisY: number
  brink: { x: number; yTop: number; yBottom: number }
  top: number
  bottom: number
}

function orderCanaries(canaries: TraceCanary[]): TraceCanary[] {
  return [...canaries].sort((a, b) => {
    const ia = LANE_ORDER.indexOf(a.lane)
    const ib = LANE_ORDER.indexOf(b.lane)
    return (ia === -1 ? LANE_ORDER.length : ia) - (ib === -1 ? LANE_ORDER.length : ib)
  })
}

interface HitCluster {
  xFrom: number
  xTo: number
  hits: TraceHit[]
}

/** Same merge rule as clusters() (within `gap` px), keeping the member hits so labels can be built from them. */
function clusterHits(hits: TraceHit[], agoOf: (h: TraceHit) => number, cxFn: (ago: number) => number, gap = 6): HitCluster[] {
  // Cluster in x order (needed to merge only near neighbours), but keep
  // each cluster's hits in the API's own order (newest first) for the
  // tried-join text -- x order and time order aren't the same thing once
  // two visitors' hits interleave on the same line.
  const withIndex = hits.map((hit, index) => ({ hit, index, x: cxFn(agoOf(hit)) }))
  const sorted = [...withIndex].sort((a, b) => a.x - b.x)
  const groups: Array<{ xFrom: number; xTo: number; items: typeof withIndex }> = []
  for (const item of sorted) {
    const last = groups[groups.length - 1]
    if (last && item.x - last.xTo <= gap) {
      last.xTo = item.x
      last.items.push(item)
    } else {
      groups.push({ xFrom: item.x, xTo: item.x, items: [item] })
    }
  }
  return groups.map((g) => ({
    xFrom: g.xFrom,
    xTo: g.xTo,
    hits: g.items.sort((a, b) => a.index - b.index).map((i) => i.hit),
  }))
}

export function buildBandModel(trace: TraceResponse, containerWidth: number): BandModel {
  const x0 = 190
  const x1 = containerWidth - 80
  const now = new Date(trace.now)
  const segs = segmentsForRange(trace.range)
  const cxFn = (ago: number) => cx(ago, segs, x0, x1)
  const agoOf = (iso: string) => (now.getTime() - new Date(iso).getTime()) / 1000

  const canaries = orderCanaries(trace.canaries)
  const bandY = canaries.map((_, i) => BAND_TOP + i * PITCH)

  const lines: BandLine[] = []
  const silentDrops: SilentDrop[] = []
  const beatMarks: BeatMark[] = []
  const bandLabels: BandLabel[] = []
  const rises: Rise[] = []

  canaries.forEach((canary, i) => {
    const y = bandY[i]
    const color = LANE_VAR[canary.lane]
    bandLabels.push({ x: x0 - 10, y: y + 3, text: canary.id, color })

    if (canary.status === 'silent' && canary.last_heartbeat_at) {
      const silentAgo = agoOf(canary.last_heartbeat_at)
      const xs = cxFn(silentAgo)
      const yd = bandY[bandY.length - 1] + 18
      lines.push({ canaryId: canary.id, lane: canary.lane, y, color, xTo: xs })
      for (const ago of beatAgos(canary.beats, now, silentAgo)) {
        beatMarks.push({ x: cxFn(ago), y })
      }
      const curveD = `M${xs.toFixed(1)},${y} C${(xs + 10).toFixed(1)},${y} ${(xs + 8).toFixed(1)},${yd} ${(xs + 20).toFixed(1)},${yd}`
      const lastHeartbeat = new Date(canary.last_heartbeat_at)
      const sentence = `${canary.id} dropped out · last heartbeat ${formatClockWithSeconds(lastHeartbeat)} · silent ${formatDuration(silentAgo)}`
      silentDrops.push({ canaryId: canary.id, y, yd, xs, curveD, color, sentence })
    } else {
      lines.push({ canaryId: canary.id, lane: canary.lane, y, color, xTo: x1 })
      for (const ago of beatAgos(canary.beats, now)) {
        beatMarks.push({ x: cxFn(ago), y })
      }
    }

    // Group hits by visitor+kind (one rise family per visitor's activity on
    // this canary), then cluster each family's x-positions the way
    // gen.py's trace() does. A cluster keeps a label only when it is
    // high-signal (a credential attempt or a poisoner answer, #59); path,
    // SMB-share and bare-service clusters are still drawn as ripples.
    const groups = new Map<string, TraceHit[]>()
    for (const hit of canary.hits) {
      const key = `${hit.visitor} ${hit.kind}`
      const list = groups.get(key)
      if (list) list.push(hit)
      else groups.set(key, [hit])
    }
    for (const hitGroup of groups.values()) {
      const clustered = clusterHits(hitGroup, (h) => agoOf(h.at), cxFn)
      let widestIdx = 0
      for (let i = 1; i < clustered.length; i++) {
        const a = clustered[i]
        const b = clustered[widestIdx]
        const wa = a.xTo - a.xFrom
        const wb = b.xTo - b.xFrom
        if (wa > wb || (wa === wb && a.hits.length > b.hits.length)) widestIdx = i
      }
      clustered.forEach((c, idx) => {
        const labelled = idx === widestIdx && isHighSignalRise(c.hits)
        const kind = c.hits[0].kind
        let l1 = ''
        let l2 = ''
        if (labelled) {
          l1 = joinTried(c.hits.map((h) => h.tried))
          const newest = c.hits.reduce((a, b) => (new Date(a.at) > new Date(b.at) ? a : b))
          l2 = buildLine2(newest.visitor, canary.id, newest.service, new Date(newest.at), now)
        }
        const times = c.hits.map((h) => new Date(h.at).getTime())
        rises.push({ xFrom: c.xFrom, xTo: c.xTo, y, kind, l1, l2, labelled, atFrom: Math.min(...times), atTo: Math.max(...times) })
      })
    }
  })

  const layout = placeRises(rises, x0, x1, BAND_TOP)
  const axisY = bandY[bandY.length - 1] + 42

  return {
    x0,
    x1,
    segs,
    bandY,
    lines,
    silentDrops,
    beatMarks,
    bandLabels,
    bumps: layout.bumps,
    labels: layout.labels,
    axisTicks: axisTicks(segs, x0, x1),
    dayTicks: dayTicks(now, segs, x0, x1),
    captions: axisCaptions(segs, x0, x1),
    now: nowLabel(now, x1),
    axisY,
    brink: { x: x1, yTop: layout.top, yBottom: bandY[bandY.length - 1] + 40 },
    top: layout.top,
    // Below the day-caption row (axisY + 16) with a little room for its
    // text height -- matches where the shots' axis captions actually end.
    bottom: axisY + 32,
  }
}

export function kindColor(kind: VisitorKind): string {
  return KIND_VAR[kind]
}

export type { Box, PlacedBump, PlacedLabel, Range }
