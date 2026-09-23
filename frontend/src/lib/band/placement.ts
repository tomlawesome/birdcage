// Port of gen.py's trace() placement loop: sort rises left to right, give
// each labelled rise the first free candidate slot (on top, hang left, hang
// right -- hang left only in the last 300px), growing its rise height by
// 30 until one is free. Unlabelled clusters stay low ripples and are never
// obstacles, same as the generator.
import type { VisitorKind } from '../types'
import { type Anchor, bumpPath, labelBox, labelWidth, LH } from './bump'

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

/** Scale options, for a caller whose line is not one of many (issue
 * #118's canary page): the unlabelled ripples are drawn taller there,
 * because there is no neighbouring line for them to run into. Omitted,
 * every number is the band's own. */
export interface PlacementOptions {
  rippleH?: number
  rippleBw?: number
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
  const obstacles: Box[] = []

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
        const top = r.y - h - LH
        const bottom = r.y - h
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

    const { anchor, ax, bx0, bx1 } = chosen
    obstacles.push({ xFrom: bx0, xTo: bx1, top: r.y - h - LH, bottom: r.y - h })
    obstacles.push({ xFrom: r.xFrom - (14 + h * 0.2), xTo: Math.min(r.xTo + (14 + h * 0.2), x1), top: r.y - h, bottom: r.y })
    const bw = 14 + h * 0.2
    bumps.push({ xFrom: r.xFrom, xTo: r.xTo, y: r.y, h, bw, kind: r.kind, d: bumpPath(r.xFrom, r.xTo, r.y, h, x1, bw), labelled: true })
    labels.push({ anchor, x: ax, y: r.y - h, kind: r.kind, l1: r.l1, l2: r.l2, box: { xFrom: bx0, xTo: bx1, top: r.y - h - LH, bottom: r.y - h } })
  }

  const top = Math.min(bandTop - 60, ...obstacles.map((o) => o.top - 10))
  return { bumps, labels, obstacles, top }
}
