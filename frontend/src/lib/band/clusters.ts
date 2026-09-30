// Port of gen.py's clusters(): merge hits whose x positions are within
// `gap` px into one [xFrom, xTo, count] run.
export interface Cluster {
  xFrom: number
  xTo: number
  count: number
}

export function clusters(agos: number[], cx: (ago: number) => number, gap = 6): Cluster[] {
  const xs = agos.map(cx).sort((a, b) => a - b)
  const out: Cluster[] = []
  for (const x of xs) {
    const last = out[out.length - 1]
    if (last && x - last.xTo <= gap) {
      last.xTo = x
      last.count += 1
    } else {
      out.push({ xFrom: x, xTo: x, count: 1 })
    }
  }
  return out
}
