// #227 review findings, page level. The API gap: the page's
// self_test_runs carry issued_at/completed_at/passed only -- no command
// id -- and the 202 body is {command_id} with no `created` flag. So the
// queued pill follows runs by time and completion, not by id:
//   queued = after a 202, until no run issued at or after the click is
//   open, and no run that was open at the click is still open.
import { cleanup, fireEvent, render } from '@testing-library/svelte'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import CanaryPage from './CanaryPage.svelte'
import { sceneInput } from './lib/canary/fixtures'

function base(mutate: (i: ReturnType<typeof sceneInput>) => void = () => {}) {
  const input = sceneInput('quiet')
  mutate(input)
  return { page: input.page, trace: input.trace, visitors: input.visitors, history: input.history, runs: null, range: '14d' as const }
}
const accepted = () => new Response(JSON.stringify({ command_id: 'c1' }), { status: 202 })
let fetchMock: ReturnType<typeof vi.fn>
beforeEach(() => {
  vi.useFakeTimers()
  fetchMock = vi.fn()
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.useRealTimers()
})
const btn = (c: HTMLElement, t: string) => [...c.querySelectorAll<HTMLButtonElement>('.acts button.pill')].find((b) => b.textContent?.trim() === t)
const flush = () => vi.advanceTimersByTimeAsync(0)
const iso = (ms: number) => new Date(ms).toISOString()

describe('queued follows the run the 202 named', () => {
  it('created=true: stays queued while the new run is listed but open, returns when it completes, and the poll stops', async () => {
    fetchMock.mockResolvedValue(accepted())
    const b = base()
    const onchanged = vi.fn()
    const { container, rerender } = render(CanaryPage, { ...b, role: 'admin', onchanged })
    await fireEvent.click(btn(container, 'run the self-test now ▸')!)
    await flush()
    expect(btn(container, 'self-test queued…')?.disabled).toBe(true)

    const t0 = Date.parse(b.page.self_test_runs[0].issued_at) + 3_600_000
    const open = structuredClone(b.page)
    open.self_test_runs.unshift({ issued_at: iso(t0) } as any)
    await rerender({ ...b, page: open })
    expect(btn(container, 'self-test queued…')?.disabled).toBe(true) // listed, not finished

    const done = structuredClone(open)
    done.self_test_runs[0] = { issued_at: iso(t0), completed_at: iso(t0 + 7000), passed: true }
    await rerender({ ...b, page: done })
    expect(btn(container, 'run the self-test now ▸')?.disabled).toBe(false)
    const calls = onchanged.mock.calls.length
    await vi.advanceTimersByTimeAsync(60_000)
    expect(onchanged.mock.calls.length).toBe(calls)
  })

  it('created=false naming an already-open run: queued, then returns when that run completes (no stick)', async () => {
    fetchMock.mockResolvedValue(accepted())
    const b = base((i) => {
      const r = i.page.self_test_runs[0]
      delete (r as any).completed_at
      delete (r as any).passed
    })
    const onchanged = vi.fn()
    const { container, rerender } = render(CanaryPage, { ...b, role: 'admin', onchanged })
    await fireEvent.click(btn(container, 'run the self-test now ▸')!)
    await flush()
    expect(btn(container, 'self-test queued…')?.disabled).toBe(true)

    const done = structuredClone(b.page)
    const issued = Date.parse(done.self_test_runs[0].issued_at)
    done.self_test_runs[0] = { issued_at: iso(issued), completed_at: iso(issued + 7000), passed: true }
    await rerender({ ...b, page: done })
    expect(btn(container, 'run the self-test now ▸')?.disabled).toBe(false)
    const calls = onchanged.mock.calls.length
    await vi.advanceTimersByTimeAsync(60_000)
    expect(onchanged.mock.calls.length).toBe(calls)
  })

  it('the run never shows: polling stops after 10 minutes (the API carries no deadline) and the pill comes back', async () => {
    fetchMock.mockResolvedValue(accepted())
    const onchanged = vi.fn()
    const { container } = render(CanaryPage, { ...base(), role: 'admin', onchanged })
    await fireEvent.click(btn(container, 'run the self-test now ▸')!)
    await flush()
    await vi.advanceTimersByTimeAsync(5 * 60_000)
    expect(btn(container, 'self-test queued…')?.disabled).toBe(true)
    expect(onchanged.mock.calls.length).toBeGreaterThan(20)
    await vi.advanceTimersByTimeAsync(5 * 60_000 + 15_000)
    const calls = onchanged.mock.calls.length
    await vi.advanceTimersByTimeAsync(120_000)
    expect(onchanged.mock.calls.length).toBe(calls)
    expect(btn(container, 'run the self-test now ▸')?.disabled).toBe(false)
  })
})

describe('a write in flight disables its pill; a double click sends one request', () => {
  it.each([
    ['run the self-test now ▸', 'quiet'],
    ['mark as maintenance · 24 h', 'quiet'],
  ])('%s', async (label) => {
    let release!: (r: Response) => void
    fetchMock.mockReturnValue(new Promise<Response>((r) => (release = r)))
    const { container } = render(CanaryPage, { ...base(), role: 'admin', onchanged: vi.fn() })
    const b = btn(container, label)!
    await fireEvent.click(b)
    await flush()
    expect(btn(container, label)?.disabled ?? btn(container, 'self-test queued…')?.disabled).toBe(true)
    await fireEvent.click(container.querySelector<HTMLButtonElement>(`.acts button.pill[disabled]`) ?? b)
    await fireEvent.click(b)
    expect(fetchMock).toHaveBeenCalledTimes(1)
    release(accepted())
    await flush()
  })

  it('the pill is usable again after a failed write', async () => {
    fetchMock.mockResolvedValueOnce(new Response('{}', { status: 500 })).mockResolvedValue(accepted())
    const { container } = render(CanaryPage, { ...base(), role: 'admin', onchanged: vi.fn() })
    await fireEvent.click(btn(container, 'mark as maintenance · 24 h')!)
    await flush()
    expect(btn(container, 'mark as maintenance · 24 h')?.disabled).toBe(false)
  })
})
