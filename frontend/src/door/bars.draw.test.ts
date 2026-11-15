// Drawing, with a recording stand-in for the 2D context (jsdom has
// none): a frozen moment draws the same strokes every time, the amber
// posts are drawn, caught pulses are cut red, an opening door moves the
// bars apart, and stopping cancels the next frame.
import { afterEach, describe, expect, it, vi } from 'vitest'
import { startBars } from './bars'

type Call = [string, ...unknown[]]

function fakeContext() {
  const calls: Call[] = []
  const gradient = () => ({ addColorStop: (...a: unknown[]) => calls.push(['stop', ...a]) })
  const ctx = new Proxy({} as Record<string, unknown>, {
    get(target, key: string) {
      if (key === 'createLinearGradient') return (...a: unknown[]) => (calls.push(['gradient', ...a]), gradient())
      if (key in target) return target[key]
      return (...a: unknown[]) => calls.push([key, ...a])
    },
    set(target, key: string, value) {
      target[key] = value
      calls.push(['set ' + key, value])
      return true
    },
  })
  return { ctx, calls }
}

function canvasWith(ctx: unknown) {
  const c = document.createElement('canvas')
  c.getContext = (() => ctx) as unknown as HTMLCanvasElement['getContext']
  return c
}

function motion(reduced: boolean) {
  vi.stubGlobal('matchMedia', (q: string) => ({ matches: reduced && q.includes('reduce'), media: q }))
}

describe('startBars drawing', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('a frozen moment draws the same frame each time, with posts and caught pulses', () => {
    motion(false)
    vi.stubGlobal('requestAnimationFrame', () => 1)
    const a = fakeContext()
    const b = fakeContext()
    startBars(canvasWith(a.ctx), { frozenAt: 14 })()
    startBars(canvasWith(b.ctx), { frozenAt: 14 })()
    expect(a.calls.length).toBeGreaterThan(100)
    expect(JSON.stringify(a.calls)).toBe(JSON.stringify(b.calls))
    expect(a.calls).toContainEqual(['set strokeStyle', '#e8b05a'])
    // something is caught by 14 s at the mock-up's seed: the red beat
    expect(a.calls.some((c) => c[0] === 'set shadowColor' && String(c[1]).startsWith('rgba(236,72,80'))).toBe(true)
  })

  it('an opening door draws the bars a full width apart', () => {
    motion(true)
    const shut = fakeContext()
    const open = fakeContext()
    startBars(canvasWith(shut.ctx))()
    startBars(canvasWith(open.ctx), { opening: () => true })()
    const xs = (calls: Call[]) => calls.filter((c) => c[0] === 'moveTo').map((c) => c[1] as number)
    const width = innerWidth
    expect(xs(open.calls)[0]).toBeCloseTo(xs(shut.calls)[0] - width)
  })

  it('animates frame by frame and slides apart once opening', () => {
    motion(false)
    let frames: FrameRequestCallback[] = []
    let requested = 0
    vi.stubGlobal('requestAnimationFrame', (f: FrameRequestCallback) => (frames.push(f), ++requested))
    const cancel = vi.fn()
    vi.stubGlobal('cancelAnimationFrame', cancel)
    let opening = false
    const { ctx, calls } = fakeContext()
    const stop = startBars(canvasWith(ctx), { opening: () => opening })
    const run = (n: number, from: number) => {
      for (let i = 0; i < n; i++) {
        const f = frames.pop()!
        frames = []
        f(from + i * 50)
      }
    }
    run(200, performance.now() + 50)
    opening = true
    calls.length = 0
    run(20, performance.now() + 20000)
    expect(calls.some((c) => c[0] === 'moveTo')).toBe(true)
    // Stopping cancels the frame last requested, and a frame the browser
    // runs anyway draws nothing and asks for no more.
    expect(frames.length).toBe(1)
    const pending = frames[0]
    stop()
    expect(cancel).toHaveBeenCalledWith(requested)
    calls.length = 0
    frames = []
    const before = requested
    pending(performance.now() + 40000)
    expect(calls).toEqual([])
    expect(requested).toBe(before)
  })

  it('a canvas whose context cannot be had draws nothing and still stops', () => {
    motion(true)
    const c = document.createElement('canvas')
    c.getContext = (() => {
      throw new Error('no context')
    }) as unknown as HTMLCanvasElement['getContext']
    const stop = startBars(c)
    expect(typeof stop).toBe('function')
    stop()
  })
})
