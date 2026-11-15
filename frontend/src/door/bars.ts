// The bars behind the door (ADR-0017 decisions 2 to 4, 6 and 8), ported
// from docs/design/concepts/round-18/bars.js with its numbers, its
// drawing and the order of its random draws unchanged, so a frozen
// moment here is the mock-up's at the same `?t=`. Restructured only as
// far as the specification's exports need: the seeded generator, the
// trace, the offset clamp and the share of caught pulses are their own
// functions; startBars() is the rest of the file. The mock-up's
// `data-glint` modes are reduced to the one it ships ('shimmer'), its
// `?t=` is opts.frozenAt, and its body `data-state === 'in'` is
// opts.opening. Every signal is drawn from a timer, never from data
// (decision 6).

/** The share of pulses that are caught: stopped part-way, cut, beating red. */
export const CAUGHT_SHARE = 0.27

/** A deterministic generator in [0, 1) (mulberry32, as the mock-up). */
export function seeded(seed: number): () => number {
  let s = seed
  return () => {
    s |= 0
    s = (s + 0x6d2b79f5) | 0
    let t = Math.imul(s ^ (s >>> 15), 1 | s)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

// The trace a pulse leaves: sharp, like activity on a line chart, and
// unruly. Spikes are mostly small with a few long ones that reach across
// the neighbouring bars; the trace flickers while it lasts. The two bars
// either side pick up a weaker trace of their own, so a pulse disturbs
// its neighbourhood, not one line.
const DY = 3
const REACH = 62
const NEAR = [1, 0.34, 0.13]
const LAG = 26

/** The sharp trace, `length` steps of DY pixels, every value within
 * ±(3 + reach). */
export function makeTrace(rnd: () => number, length: number, reach: number): Float32Array {
  const a = new Float32Array(length)
  let burst = 0,
    sign = 1,
    hold = 0
  for (let i = 0; i < length; i++) {
    if (burst <= 0 && rnd() < 0.07) burst = 3 + Math.floor(rnd() * rnd() * 26)
    if (burst > 0) {
      burst--
      if (hold > 0) {
        hold--
        a[i] = a[i - 1] || 0
        continue
      }
      sign = rnd() < 0.72 ? -sign : sign
      a[i] = sign * (3 + Math.pow(rnd(), 3.2) * reach)
      if (rnd() < 0.22) a[i] = 0
      if (rnd() < 0.18) hold = 1 + Math.floor(rnd() * 3)
    } else a[i] = rnd() < 0.1 ? (rnd() - 0.5) * 5 : 0
  }
  return a
}

/** A bar's sideways offset, never beyond ±REACH; the bar next to an
 * amber post (barIndex 1) never more than 36 towards the form, so
 * nothing crosses the posts into the form. side is -1 left of the form,
 * +1 right. */
export function clampOffset(v: number, barIndex: number, side: number): number {
  v = Math.max(-REACH, Math.min(REACH, v))
  if (barIndex === 1 && v * side < 0) v = Math.max(-36, Math.min(36, v))
  return v
}

export interface BarsOptions {
  /** Seconds: run the simulation this long from the seed and draw one
   * still frame (the mock-up's `?t=`). */
  frozenAt?: number
  /** True once the door is opening: the two halves slide apart. */
  opening?: () => boolean
}

type RGB = number[]
interface Bar {
  x: number
  side: number
  n: number
  ph: number
  sp: number
  k: number
}
interface Pulse {
  bar: Bar
  col: RGB
  t0: number
  id: number
  tr: Float32Array[]
  stop?: number
  tc?: number
}

const SEED = 20261115
const COL: RGB[] = [
  [57, 135, 229],
  [25, 158, 112],
  [232, 176, 90],
  [215, 106, 158],
]
const RED: RGB = [236, 72, 80]
const GAP = 210,
  STEP = 46,
  PULSE = 130,
  RISE = 2.6
const HOLD = 2.7

function reducedMotion(): boolean {
  return typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches
}

/** Draws and animates the bars on canvas; returns the stop function. */
export function startBars(c: HTMLCanvasElement, opts: BarsOptions = {}): () => void {
  let x: CanvasRenderingContext2D | null = null
  try {
    x = c.getContext('2d')
  } catch {
    x = null
  }
  // No animation frames to ask for (a test DOM) is drawn as still, too.
  const STILL = reducedMotion() || typeof requestAnimationFrame !== 'function'
  const FROZEN = opts.frozenAt ?? null
  const isOpening = opts.opening ?? (() => false)
  const rnd = seeded(SEED)
  let W = 0,
    H = 0,
    D = 1,
    bars: Bar[] = [],
    pulses: Pulse[] = [],
    next = 0.6,
    open = 0,
    T = 0

  function size() {
    D = Math.min(devicePixelRatio || 1, 2)
    W = innerWidth
    H = innerHeight
    c.width = W * D
    c.height = H * D
    bars = []
    for (let n = 0; W / 2 - GAP - n * STEP > -2; n++) {
      bars.push({ x: W / 2 - GAP - n * STEP, side: -1, n, ph: rnd() * 9, sp: 0.05 + rnd() * 0.06, k: Math.floor(rnd() * 4) })
      bars.push({ x: W / 2 + GAP + n * STEP, side: 1, n, ph: rnd() * 9, sp: 0.05 + rnd() * 0.06, k: Math.floor(rnd() * 4) })
    }
  }

  function step(dt: number) {
    T += dt
    if (T >= next) {
      const free = bars.filter((b) => b.n > 0 && !pulses.some((p) => p.bar === b))
      if (free.length) pulses.push(newPulse(free[Math.floor(rnd() * free.length)]))
      next = T + 0.35 + rnd() * rnd() * 2.6
    }
    pulses = pulses.filter((p) => (p.stop != null ? T - p.tc! < HOLD : T - p.t0 < RISE + 2.2))
  }

  // About one pulse in four is caught: it stops dead part-way up, the bar
  // is cut there and pulses red, then mends.
  const head = (p: Pulse) => {
    const h = H + 20 - ((T - p.t0) / RISE) * (H + PULSE + 40)
    return p.stop != null ? Math.max(h, p.stop) : h
  }
  const ca = (p: Pulse) => (p.stop == null ? -1 : T - p.tc!) // seconds since it was caught
  const live = (p: Pulse) => {
    const a = ca(p)
    return a <= 0 ? 1 : Math.max(0, 1 - a / 0.4)
  }
  const hsh = (i: number, j: number) => {
    const v = Math.sin(i * 127.1 + j * 311.7) * 43758.5453
    return v - Math.floor(v)
  }
  const trace = (big: number) => makeTrace(rnd, Math.ceil((innerHeight + 400) / DY), big)
  const newPulse = (bar: Bar): Pulse => {
    const p: Pulse = { bar, col: COL[Math.floor(rnd() * 4)], t0: T, id: Math.floor(rnd() * 1e4), tr: [trace(REACH), trace(REACH), trace(REACH)] }
    if (rnd() < CAUGHT_SHARE) {
      p.stop = H * (0.2 + rnd() * 0.5)
      p.tc = T + ((H + 20 - p.stop) / (H + PULSE + 40)) * RISE
    }
    return p
  }
  function part(p: Pulse, k: number, y: number) {
    // what pulse p does at height y to a bar k places away from its own
    const d = y - head(p) - k * LAG
    if (d <= 0) return 0
    const env = Math.min(1, d / 5) * (d < 240 ? 1 : Math.max(0, 1 - (d - 240) / 320))
    if (env <= 0) return 0
    const i = Math.max(0, Math.floor((y + 120) / DY)),
      v = p.tr[k][i] || 0
    if (!v) return 0
    return v * NEAR[k] * env * live(p) * (0.45 + 1.0 * hsh(i + p.id + k * 97, Math.floor(T * 13)))
  }
  const near = (b: Bar) => (b.n === 0 ? [] : pulses.filter((p) => p.bar.side === b.side && Math.abs(p.bar.n - b.n) <= 2))
  function off(b: Bar, ps: Pulse[], y: number) {
    let v = 0
    for (const p of ps) v += part(p, Math.abs(p.bar.n - b.n), y)
    return clampOffset(v, b.n, b.side)
  }

  function draw() {
    if (!x) return
    const g2 = x
    const path = (b: Bar, ps: Pulse[] | null, y0: number, y1: number) => {
      const bx = b.x + b.side * open
      g2.beginPath()
      if (!ps || !ps.length) {
        g2.moveTo(bx, y0)
        g2.lineTo(bx, y1)
        return
      }
      y0 = Math.floor(y0 / DY) * DY
      for (let y = y0; y <= y1 + DY; y += DY) {
        const X = bx + off(b, ps, y)
        if (y === y0) g2.moveTo(X, y)
        else g2.lineTo(X, y)
      }
    }
    g2.setTransform(D, 0, 0, D, 0, 0)
    g2.clearRect(0, 0, W, H)
    g2.lineCap = 'butt'
    g2.lineJoin = 'miter'
    const base = g2.createLinearGradient(0, 0, 0, H)
    base.addColorStop(0, 'rgba(160,185,230,.42)')
    base.addColorStop(0.7, 'rgba(160,185,230,.10)')
    base.addColorStop(1, 'rgba(160,185,230,.04)')
    for (const b of bars) {
      const p = near(b)
      if (b.n === 0) {
        g2.shadowColor = 'rgba(232,176,90,.45)'
        g2.shadowBlur = 14
        g2.strokeStyle = '#e8b05a'
        g2.lineWidth = 1.5
        path(b, null, 0, H)
        g2.stroke()
        g2.shadowBlur = 0
        continue
      }
      g2.strokeStyle = base
      g2.lineWidth = 1.5
      path(b, p, 0, H)
      g2.stroke()
      // shimmer: each bar carries a faint drifting patch of colour
      const yy = H * (0.5 + 0.62 * Math.sin(T * b.sp * 2.2 + b.ph)),
        a = 0.22 + 0.68 * Math.max(0, Math.sin(T * b.sp * 1.3 + b.ph * 2.1)) ** 2,
        cc = COL[b.k]
      const g = g2.createLinearGradient(0, yy - 200, 0, yy + 200)
      g.addColorStop(0, `rgba(${cc},0)`)
      g.addColorStop(0.5, `rgba(${cc},${a})`)
      g.addColorStop(1, `rgba(${cc},0)`)
      g2.strokeStyle = g
      path(b, p, 0, H)
      g2.stroke()
    }
    for (const p of pulses) {
      // the disturbed stretch takes the pulse's colour, on its own bar and fainter on the neighbours
      const h = head(p)
      if (h > H) continue
      for (const b of bars) {
        if (b.side !== p.bar.side || b.n === 0) continue
        const k = Math.abs(b.n - p.bar.n)
        if (k > 2) continue
        const y0 = Math.max(0, h + k * LAG),
          y1 = Math.min(H, y0 + 560)
        if (y1 <= y0) continue
        const g = g2.createLinearGradient(0, h + k * LAG, 0, h + k * LAG + 560),
          a = [0.85, 0.5, 0.28][k] * live(p)
        g.addColorStop(0, `rgba(${p.col},${a})`)
        g.addColorStop(0.45, `rgba(${p.col},${a * 0.7})`)
        g.addColorStop(1, `rgba(${p.col},0)`)
        g2.strokeStyle = g
        g2.lineWidth = k ? 1.2 : 1.5
        path(b, near(b), y0, y1)
        g2.stroke()
      }
    }
    for (const p of pulses) {
      // the pulse itself, following the bar
      const h = head(p),
        f = live(p)
      if (h < -PULSE - 10 || f <= 0) continue
      const col = ca(p) > 0 ? RED : p.col
      const g = g2.createLinearGradient(0, h, 0, h + PULSE)
      g.addColorStop(0, `rgba(${col},0)`)
      g.addColorStop(0.04, `rgba(255,255,255,${0.95 * f})`)
      g.addColorStop(0.3, `rgba(${col},${0.95 * f})`)
      g.addColorStop(1, `rgba(${col},0)`)
      g2.shadowColor = `rgba(${col},.9)`
      g2.shadowBlur = 9
      g2.strokeStyle = g
      g2.lineWidth = 1.8
      path(p.bar, near(p.bar), Math.max(0, h), Math.min(H, h + PULSE))
      g2.stroke()
      g2.shadowBlur = 0
    }
    for (const p of pulses) {
      // caught: the cut, the red beat, the mend
      const a = ca(p)
      if (a <= 0) continue
      const bx = p.bar.x + p.bar.side * open,
        y = p.stop!
      const beat = Math.exp(-a * 1.25) * (0.5 + 0.5 * Math.cos(a * 15)) + 0.22 * Math.max(0, 1 - a / HOLD),
        A = Math.min(1, beat) * Math.min(1, (HOLD - a) / 0.5)
      const gap = 8 * (a < 0.1 ? a / 0.1 : a < 1.7 ? 1 : Math.max(0, 1 - (a - 1.7) / 0.8))
      const g = g2.createLinearGradient(0, y - 190, 0, y + 190)
      g.addColorStop(0, `rgba(${RED},0)`)
      g.addColorStop(0.5, `rgba(${RED},${A})`)
      g.addColorStop(1, `rgba(${RED},0)`)
      g2.shadowColor = `rgba(${RED},${A})`
      g2.shadowBlur = 12
      g2.strokeStyle = g
      g2.lineWidth = 1.8
      g2.beginPath()
      g2.moveTo(bx, y - 190)
      g2.lineTo(bx, y + 190)
      g2.stroke()
      g2.shadowBlur = 0
      if (gap > 0.3) {
        g2.clearRect(bx - 5, y - gap, 10, gap * 2)
        g2.strokeStyle = `rgba(${RED},${Math.min(1, 0.35 + A)})`
        g2.lineWidth = 1.5
        g2.beginPath()
        g2.moveTo(bx - 5, y - gap)
        g2.lineTo(bx + 5, y - gap)
        g2.moveTo(bx - 5, y + gap)
        g2.lineTo(bx + 5, y + gap)
        g2.stroke()
      }
    }
  }

  size()
  addEventListener('resize', size)
  if (FROZEN != null || STILL) {
    if (!STILL) for (let i = 0; i < FROZEN! * 60; i++) step(1 / 60)
    else T = 20
    if (isOpening()) open = W
    draw()
    addEventListener('resize', draw)
    return () => {
      removeEventListener('resize', size)
      removeEventListener('resize', draw)
    }
  }
  let last = performance.now(),
    t0open: number | null = null,
    frame = 0,
    stopped = false
  const loop = (now: number) => {
    if (stopped) return
    const dt = Math.min(0.05, (now - last) / 1000)
    last = now
    step(dt)
    if (isOpening()) {
      t0open ??= now
      const u = Math.min(1, (now - t0open) / 700)
      open = (W / 2) * (u < 0.5 ? 4 * u * u * u : 1 - Math.pow(-2 * u + 2, 3) / 2)
    } else {
      t0open = null
      open = 0
    }
    draw()
    frame = requestAnimationFrame(loop)
  }
  loop(last)
  return () => {
    stopped = true
    if (typeof cancelAnimationFrame === 'function') cancelAnimationFrame(frame)
    removeEventListener('resize', size)
  }
}
