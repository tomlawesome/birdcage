// Port of gen.py's bump(): a smooth rise from the line -- up over `w`,
// flat across the cluster, down over `w`. Returns the path `d` the
// generator draws twice (once filled at low opacity, once stroked).
export function bumpPath(x0: number, x1: number, y: number, h: number, x1Limit: number, w = 16): string {
  const a = x0 - w
  const b = Math.min(x1 + w, x1Limit)
  return (
    `M${a.toFixed(1)},${y} C${(a + w * 0.55).toFixed(1)},${y} ${(x0 - w * 0.45).toFixed(1)},${y - h} ${x0.toFixed(1)},${y - h} ` +
    `L${x1.toFixed(1)},${y - h} C${(x1 + (b - x1) * 0.45).toFixed(1)},${y - h} ${(b - (b - x1) * 0.55).toFixed(1)},${y} ${b.toFixed(1)},${y}`
  )
}

// Port of gen.py's CH/LH constants: px per mono character at 10.5px, and
// a two-line label's height.
export const CH = 6.4
export const LH = 28

/** Port of gen.py's shared width formula used by both label_box and the placement loop. */
export function labelWidth(l1: string, l2: string, ch = CH): number {
  return Math.max(l1.length + 2, l2.length * 0.9) * ch
}

export type Anchor = 'start' | 'middle' | 'end'

export interface LabelBox {
  anchor: Anchor
  anchorX: number
  xFrom: number
  xTo: number
}

/** Port of gen.py's label_box(): where a label centred on x would sit. */
export function labelBox(x: number, l1: string, l2: string, x0: number, x1: number, ch = CH): LabelBox {
  const w = labelWidth(l1, l2, ch)
  if (x + w / 2 > x1) {
    return { anchor: 'end', anchorX: x1, xFrom: x1 - w, xTo: x1 }
  }
  if (x - w / 2 < x0) {
    return { anchor: 'start', anchorX: x0, xFrom: x0, xTo: x0 + w }
  }
  return { anchor: 'middle', anchorX: x, xFrom: x - w / 2, xTo: x + w / 2 }
}
