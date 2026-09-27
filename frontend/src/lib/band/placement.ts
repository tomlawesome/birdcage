// Port of gen.py's trace() placement loop: sort rises left to right, give
// each labelled rise the first free candidate slot (on top, hang left, hang
// right -- hang left only in the last 300px), growing its rise height by
// 30 until one is free. Unlabelled clusters stay low ripples and are never
// obstacles, same as the generator.
//
// Issue #58: gen.py never bounded that growth, so four coincident rises
// could stack their labels straight off the top of the chart and into the
// hero sentence or the header above it. The growth loop below is now
// bounded by CHART_TOP -- a label that would cross it, and every rise
// after it that is still part of the same pile-up, folds into one counted
// banner at the chart's own top edge instead. This is a deliberate
// departure from the gen.py port, not a redesign of it: gen.py's own
// mockups never exercised four canaries' credential rises landing this
// close together.
import type { VisitorKind } from '../types'
import { type Anchor, bumpPath, labelBox, labelWidth, LH } from './bump'
import { formatClock } from './format'

export interface Rise {
  xFrom: number
  xTo: number
  y: number
  kind: VisitorKind
  l1: string
  l2: string
  /** Only the widest cluster for a given (canary, visitor, kind) is labelled; the rest are ripples. */
  labelled: boolean
  /** The height to try first, where the caller has a scale of its own.
   * The band leaves it unset and every rise starts at START_H; the
   * canary page (issue #118) has one line and room above it, so it asks
   * for gen.py's round-7 heights directly. The growth loop is unchanged
   * either way -- this is where a rise starts, not a height it keeps. */
  h?: number
  /** Earliest and latest hit (ms epoch) behind this rise's cluster. Only
   * read if the rise ends up folded into a collapsed banner (#58), to
   * say the span of what got hidden -- unused otherwise. */
  atFrom: number
  atTo: number
}

export interface PlacedBump {
  xFrom: number
  xTo: number
  y: number
  h: number
  bw: number
  kind: VisitorKind
  d: string
  labelled: boolean
}

export interface PlacedLabel {
  anchor: Anchor
  x: number
  y: number
  kind: VisitorKind
  l1: string
  l2: string
  box: Box
  /** SVG path joining the rise's peak to the label (#59): a hairline
   * vertical stem that bends across to the label if a bump moved it aside. */
  stem: string
}

export interface Box {
  xFrom: number
  xTo: number
  top: number
  bottom: number
}

export interface TraceLayout {
  bumps: PlacedBump[]
  labels: PlacedLabel[]
  /** Obstacle boxes used during placement: one label-text box and one bump-footprint box per labelled rise (gen.py's `placed`). */
  obstacles: Box[]
  /** Topmost y a label box reaches, or bandTop if nothing is placed -- feeds the brink line and the crop bounds. */
  top: number
}

const RIPPLE_H = 16
const RIPPLE_BW = 12
const START_H = 34
const H_STEP = 30
/** Gap between a rise's peak and its label, spanned by the stem (#59) --
 * the same hairline round 7 draws between a failed self-test tick and its
 * words (single.ts). The label is placed this far above the peak and the
 * stem joins the two. */
const STEM_H = 14

/** The chart's own top edge (#58): no label box may reach above this y,
 * on either page that draws a trace. Both put the hero sentence at 94px
 * and the sub sentence at 134px (App.svelte's .hero/.sub, CanaryPage's
 * copy of the same) above a band that starts at 290 (BAND_TOP) or 300
 * (single.ts's LINE_Y) -- 190 clears the sub sentence's tallest wrap
 * with room to spare, on either scale. */
export const CHART_TOP = 190

/** Scale options, for a caller whose line is not one of many (issue
 * #118's canary page): the unlabelled ripples are drawn taller there,
 * because there is no neighbouring line for them to run into. Omitted,
 * every number is the band's own. */
export interface PlacementOptions {
  rippleH?: number
  rippleBw?: number
}

/** Who an obstacle box speaks for, so the collapse rule (#58) can pull an
 * already-placed individual label back in when it is the very thing
 * blocking the collapsed banner from landing without overprinting it --
 * "join the cluster rather than overprinting", not just for a rise still
 * arriving but for one already on the chart. */
interface Owner {
  rise: Rise
  label: PlacedLabel
  bump: PlacedBump
}

export function placeRises(
  rises: Rise[],
  x0: number,
  x1: number,
  bandTop: number,
  options: PlacementOptions = {},
): TraceLayout {
  const rippleH = options.rippleH ?? RIPPLE_H
  const rippleBw = options.rippleBw ?? RIPPLE_BW
  const sorted = [...rises].sort((a, b) => a.xFrom - b.xFrom)
  const bumps: PlacedBump[] = []
  const labels: PlacedLabel[] = []
  let obstacles: Box[] = []
  const ownerOf = new Map<Box, Owner>()
  const removedLabels = new Set<PlacedLabel>()

  // Issue #58: a run of rises that would stack their labels past
  // CHART_TOP folds into one banner instead. `pending` is that run,
  // still being gathered -- `obstacle` is its provisional footprint
  // (mutated in place as more rises join, so it is already live in
  // `obstacles` and later rises correctly avoid it). Closed out the
  // moment a rise finds room on its own, since rises are walked left to
  // right and nothing further right will ever reach back to join it.
  let pending: {
    xFrom: number
    xTo: number
    count: number
    atFrom: number
    atTo: number
    kind: VisitorKind
    obstacle: Box
  } | null = null

  const shrinkToRipple = (owner: Owner) => {
    // No longer an individual label above it to clear room for -- back
    // to the plain shape a rise this size would otherwise draw.
    const h0 = owner.rise.h ?? START_H
    const bw0 = 14 + h0 * 0.2
    owner.bump.h = h0
    owner.bump.bw = bw0
    owner.bump.labelled = false
    owner.bump.d = bumpPath(owner.rise.xFrom, owner.rise.xTo, owner.rise.y, h0, x1, bw0)
  }

  const finalizePending = () => {
    if (!pending) return
    const p = pending
    const labelY = CHART_TOP + LH

    // The banner still must not overprint an individual label already
    // sitting where it would go -- try the same three candidate anchors
    // an ordinary rise does, and when every one is blocked, absorb
    // whichever already-placed label is in the way (extending the
    // banner's own count and span) rather than draw over it. Absorbing
    // only ever removes obstacles, so this terminates.
    let chosen: { anchor: Anchor; ax: number; bx0: number; bx1: number } | null = null
    for (let guard = 0; guard < rises.length + 1 && !chosen; guard++) {
      const mid = (p.xFrom + p.xTo) / 2
      const l1 = `+${p.count} more`
      const l2 = `${formatClock(new Date(p.atFrom))}–${formatClock(new Date(p.atTo))}`
      const w = labelWidth(l1, l2)
      const cands: Array<[Anchor, number]> = (() => {
        const box = labelBox(mid, l1, l2, x0, x1)
        return [
          [box.anchor, box.anchorX],
          ['end', p.xFrom - w * 0.15 - 20],
          ['start', Math.min(p.xTo, x1) + 20],
        ]
      })()

      let leastBlocked: Box[] = []
      for (const [anchor, ax] of cands) {
        const bx0 = anchor === 'end' ? ax - w : anchor === 'start' ? ax : ax - w / 2
        const bx1 = anchor === 'end' ? ax : anchor === 'start' ? ax + w : ax + w / 2
        if (bx0 < x0 - 140 || bx1 > x1) continue
        const blockers = obstacles.filter(
          (o) => o !== p.obstacle && bx0 < o.xTo + 8 && bx1 > o.xFrom - 8 && CHART_TOP < o.bottom + 6 && labelY > o.top - 6,
        )
        if (blockers.length === 0) {
          chosen = { anchor, ax, bx0, bx1 }
          break
        }
        if (leastBlocked.length === 0 || blockers.length < leastBlocked.length) leastBlocked = blockers
      }
      if (chosen) break

      const owners = new Set(leastBlocked.map((o) => ownerOf.get(o)).filter((o): o is Owner => !!o))
      if (owners.size === 0) break // nothing left to absorb; settle below
      for (const owner of owners) {
        removedLabels.add(owner.label)
        p.xFrom = Math.min(p.xFrom, owner.rise.xFrom)
        p.xTo = Math.max(p.xTo, owner.rise.xTo)
        p.count += 1
        p.atFrom = Math.min(p.atFrom, owner.rise.atFrom)
        p.atTo = Math.max(p.atTo, owner.rise.atTo)
        shrinkToRipple(owner)
      }
      obstacles = obstacles.filter((o) => !owners.has(ownerOf.get(o)!))
    }

    const l1 = `+${p.count} more`
    const l2 = `${formatClock(new Date(p.atFrom))}–${formatClock(new Date(p.atTo))}`
    const mid = (p.xFrom + p.xTo) / 2
    const w = labelWidth(l1, l2)
    const { anchor, ax, bx0, bx1 } = chosen ?? { anchor: 'middle' as Anchor, ax: mid, bx0: mid - w / 2, bx1: mid + w / 2 }

    p.obstacle.xFrom = bx0
    p.obstacle.xTo = bx1
    p.obstacle.top = CHART_TOP
    p.obstacle.bottom = labelY
    labels.push({
      anchor,
      x: ax,
      y: labelY,
      kind: p.kind,
      l1,
      l2,
      box: { xFrom: bx0, xTo: bx1, top: CHART_TOP, bottom: labelY },
      // No single peak to climb from once several rises are folded
      // together -- a bare moveto draws nothing.
      stem: `M${mid.toFixed(1)},${labelY.toFixed(1)}`,
    })
    pending = null
  }

  for (const r of sorted) {
    if (!r.labelled) {
      bumps.push({
        xFrom: r.xFrom,
        xTo: r.xTo,
        y: r.y,
        h: rippleH,
        bw: rippleBw,
        kind: r.kind,
        d: bumpPath(r.xFrom, r.xTo, r.y, rippleH, x1, rippleBw),
        labelled: false,
      })
      continue
    }

    const w = labelWidth(r.l1, r.l2)
    let h = r.h ?? START_H
    let chosen: { anchor: Anchor; ax: number; bx0: number; bx1: number } | null = null

    while (!chosen) {
      // The stack would cross the chart's top edge at this height --
      // growing further only climbs higher, so stop rather than loop
      // forever, and fold this rise into the collapsed cluster below.
      if (r.y - h - STEM_H - LH < CHART_TOP) break

      const bw = 14 + h * 0.2
      const mid = (r.xFrom + r.xTo) / 2
      const cands: Array<[Anchor, number]> =
        mid > x1 - 300
          ? [['end', r.xFrom - bw - 6]]
          : (() => {
              const box = labelBox(mid, r.l1, r.l2, x0, x1)
              return [
                [box.anchor, box.anchorX],
                ['end', r.xFrom - bw - 6],
                ['start', Math.min(r.xTo, x1) + bw + 6],
              ]
            })()

      for (const [anchor, ax] of cands) {
        const bx0 = anchor === 'end' ? ax - w : anchor === 'start' ? ax : ax - w / 2
        const bx1 = anchor === 'end' ? ax : anchor === 'start' ? ax + w : ax + w / 2
        if (bx0 < x0 - 140 || bx1 > x1) continue
        const top = r.y - h - STEM_H - LH
        const bottom = r.y - h - STEM_H
        const blocked = obstacles.some(
          (p) => bx0 < p.xTo + 8 && bx1 > p.xFrom - 8 && top < p.bottom + 6 && bottom > p.top - 6,
        )
        if (!blocked) {
          chosen = { anchor, ax, bx0, bx1 }
          break
        }
      }
      if (!chosen) h += H_STEP
    }

    if (!chosen) {
      if (pending) {
        pending.xFrom = Math.min(pending.xFrom, r.xFrom)
        pending.xTo = Math.max(pending.xTo, r.xTo)
        pending.count += 1
        pending.atFrom = Math.min(pending.atFrom, r.atFrom)
        pending.atTo = Math.max(pending.atTo, r.atTo)
        pending.obstacle.xFrom = pending.xFrom - 8
        pending.obstacle.xTo = pending.xTo + 8
      } else {
        const obstacle: Box = { xFrom: r.xFrom - 8, xTo: r.xTo + 8, top: CHART_TOP, bottom: CHART_TOP + LH }
        obstacles.push(obstacle)
        pending = { xFrom: r.xFrom, xTo: r.xTo, count: 1, atFrom: r.atFrom, atTo: r.atTo, kind: r.kind, obstacle }
      }
      // The rise itself still happened -- its shape stays, at its own
      // starting height, since there is no longer an individual label
      // above it to clear room for.
      const h0 = r.h ?? START_H
      const bw0 = 14 + h0 * 0.2
      bumps.push({
        xFrom: r.xFrom,
        xTo: r.xTo,
        y: r.y,
        h: h0,
        bw: bw0,
        kind: r.kind,
        d: bumpPath(r.xFrom, r.xTo, r.y, h0, x1, bw0),
        labelled: false,
      })
      continue
    }

    // A free slot was found within budget: nothing still to come will
    // reach back to join a collapse in progress, so close it out first.
    finalizePending()

    const { anchor, ax, bx0, bx1 } = chosen
    const peakY = r.y - h
    const labelY = peakY - STEM_H
    const labelObstacle: Box = { xFrom: bx0, xTo: bx1, top: labelY - LH, bottom: labelY }
    const bumpObstacle: Box = { xFrom: r.xFrom - (14 + h * 0.2), xTo: Math.min(r.xTo + (14 + h * 0.2), x1), top: peakY, bottom: r.y }
    obstacles.push(labelObstacle, bumpObstacle)
    const bw = 14 + h * 0.2
    // The stem's foot is the rise's own x (its peak centre), so it is fixed
    // before any bump moved the label sideways; it climbs straight and then
    // bends across to the label's final anchor x if the label did move.
    const mid = (r.xFrom + r.xTo) / 2
    const stem =
      Math.abs(ax - mid) < 0.5
        ? `M${mid.toFixed(1)},${peakY.toFixed(1)} L${mid.toFixed(1)},${labelY.toFixed(1)}`
        : `M${mid.toFixed(1)},${peakY.toFixed(1)} L${mid.toFixed(1)},${(labelY + STEM_H * 0.5).toFixed(1)} L${ax.toFixed(1)},${labelY.toFixed(1)}`
    const bump: PlacedBump = { xFrom: r.xFrom, xTo: r.xTo, y: r.y, h, bw, kind: r.kind, d: bumpPath(r.xFrom, r.xTo, r.y, h, x1, bw), labelled: true }
    const label: PlacedLabel = { anchor, x: ax, y: labelY, kind: r.kind, l1: r.l1, l2: r.l2, box: labelObstacle, stem }
    bumps.push(bump)
    labels.push(label)
    const owner: Owner = { rise: r, label, bump }
    ownerOf.set(labelObstacle, owner)
    ownerOf.set(bumpObstacle, owner)
  }
  finalizePending()

  const keptLabels = labels.filter((l) => !removedLabels.has(l))
  const top = Math.min(bandTop - 60, ...obstacles.map((o) => o.top - 10))
  return { bumps, labels: keptLabels, obstacles, top }
}
