// #227 frontend slice: the canary page's admin actions (the self-test
// and maintenance pills) and how maintenance shows on the page. Written
// from the spec ("View decision (2026-11-21)" + "Spec amendment") alone.
//
// Interface these tests fix for the builder:
//   - CanaryPage takes `role?: string` (session.role; pills only for
//     'admin') and `onchanged?: () => void`, which the page calls after
//     any 2xx write and every 10 s while a self-test is queued -- App
//     owns the fetching and answers it with fetchCanary.
//   - Writes go through sendJSON (X-Requested-With: birdcage, 401 ->
//     the onSignedOut handler).
import { cleanup, fireEvent, render } from '@testing-library/svelte'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import CanaryPage from './CanaryPage.svelte'
import { onSignedOut } from './lib/api'
import { sceneInput, type SceneName } from './lib/canary/fixtures'

const UNTIL = '2026-09-13T22:00:00Z' // a Sunday
const STAMP = 'sun 13 sep 22:00'

function props(scene: SceneName, mutate: (i: ReturnType<typeof sceneInput>) => void = () => {}) {
  const input = sceneInput(scene)
  mutate(input)
  return { page: input.page, trace: input.trace, visitors: input.visitors, history: input.history, runs: null, range: '14d' as const }
}

function problem(status: number, detail = 'secret internal detail') {
  return new Response(JSON.stringify({ type: 'about:blank', title: 'x', status, detail }), {
    status,
    headers: { 'Content-Type': 'application/problem+json' },
  })
}

let fetchMock: ReturnType<typeof vi.fn>
beforeEach(() => {
  fetchMock = vi.fn()
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.useRealTimers()
})

function pill(container: HTMLElement, text: string | RegExp): HTMLButtonElement | undefined {
  return [...container.querySelectorAll<HTMLButtonElement>('.acts button.pill')].find((b) =>
    typeof text === 'string' ? b.textContent?.trim() === text : text.test(b.textContent ?? ''),
  )
}
const flush = () => vi.advanceTimersByTimeAsync(0)

describe('who sees the pills', () => {
  it('an admin gets real buttons with the exact wordings', () => {
    const { container } = render(CanaryPage, { ...props('quiet'), role: 'admin' })
    expect(pill(container, 'run the self-test now ▸')).toBeTruthy()
    expect(pill(container, 'mark as maintenance · 24 h')).toBeTruthy()
    for (const b of container.querySelectorAll('.acts .pill')) expect(b.tagName).toBe('BUTTON')
  })

  it.each(['viewer', 'user', undefined])('role %s gets no pills and no actions container', (role) => {
    const { container } = render(CanaryPage, { ...props('quiet'), role })
    expect(container.querySelector('.acts')).toBeNull()
    expect(container.textContent).not.toContain('run the self-test now')
    expect(container.textContent).not.toContain('mark as maintenance')
  })

  it('a silent canary gets no self-test pill, but still the maintenance one', () => {
    const { container } = render(CanaryPage, { ...props('silent'), role: 'admin' })
    expect(container.textContent).not.toContain('run the self-test now')
    expect(pill(container, 'mark as maintenance · 24 h')).toBeTruthy()
  })

  it('the WRITE_ROUTES_LIVE gate is deleted, not flipped', async () => {
    const mod = await import('./lib/writeActions')
    expect('WRITE_ROUTES_LIVE' in mod).toBe(false)
  })
})

describe('the self-test pill', () => {
  it('POSTs the canary self-test route with the CSRF header, then refetches', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ command_id: 'c1' }), { status: 202 }))
    const onchanged = vi.fn()
    const { container } = render(CanaryPage, { ...props('quiet'), role: 'admin', onchanged })
    await fireEvent.click(pill(container, 'run the self-test now ▸')!)
    await vi.waitFor(() => expect(onchanged).toHaveBeenCalled())
    expect(fetchMock).toHaveBeenCalledTimes(1)
    const [url, init] = fetchMock.mock.calls[0]
    expect(url).toBe('/api/admin/canaries/canary-iot/self-test')
    expect(init.method).toBe('POST')
    expect(init.headers['X-Requested-With']).toBe('birdcage')
  })

  it('after a 202 it reads "self-test queued…", disabled and quiet, and polls every 10 s', async () => {
    vi.useFakeTimers()
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ command_id: 'c1' }), { status: 202 }))
    const onchanged = vi.fn()
    const { container } = render(CanaryPage, { ...props('quiet'), role: 'admin', onchanged })
    await fireEvent.click(pill(container, 'run the self-test now ▸')!)
    await flush()
    const queued = pill(container, 'self-test queued…')!
    expect(queued).toBeTruthy()
    expect(queued.disabled).toBe(true)
    expect(queued.classList.contains('quiet')).toBe(true)
    const after = onchanged.mock.calls.length // the refetch after the 2xx
    await vi.advanceTimersByTimeAsync(10_000)
    expect(onchanged.mock.calls.length).toBe(after + 1)
    await vi.advanceTimersByTimeAsync(10_000)
    expect(onchanged.mock.calls.length).toBe(after + 2)
    // clicking the disabled pill sends nothing
    await fireEvent.click(queued)
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('stays queued while the newest run is unchanged, and returns once a newer run shows', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ command_id: 'c1' }), { status: 202 }))
    const base = props('quiet')
    const { container, rerender } = render(CanaryPage, { ...base, role: 'admin' })
    await fireEvent.click(pill(container, 'run the self-test now ▸')!)
    await vi.waitFor(() => expect(pill(container, 'self-test queued…')).toBeTruthy())

    await rerender({ ...base, page: structuredClone(base.page) }) // a fetch, nothing new
    expect(pill(container, 'self-test queued…')?.disabled).toBe(true)

    const newer = structuredClone(base.page)
    const latest = newer.self_test_runs[0].issued_at
    newer.self_test_runs.unshift({
      issued_at: new Date(Date.parse(latest) + 3_600_000).toISOString(),
      completed_at: new Date(Date.parse(latest) + 3_600_007).toISOString(),
      passed: true,
    })
    await rerender({ ...base, page: newer })
    expect(pill(container, 'run the self-test now ▸')?.disabled).toBe(false)
    expect(pill(container, 'self-test queued…')).toBeUndefined()
  })
})

describe('the maintenance pill', () => {
  it('PUTs with no body and no confirm, then refetches', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ maintenance_until: UNTIL }), { status: 200 }))
    const confirm = vi.fn(() => true)
    vi.stubGlobal('confirm', confirm)
    const onchanged = vi.fn()
    const { container } = render(CanaryPage, { ...props('quiet'), role: 'admin', onchanged })
    await fireEvent.click(pill(container, 'mark as maintenance · 24 h')!)
    await vi.waitFor(() => expect(onchanged).toHaveBeenCalled())
    const [url, init] = fetchMock.mock.calls[0]
    expect(url).toBe('/api/admin/canaries/canary-iot/maintenance')
    expect(init.method).toBe('PUT')
    expect(init.headers['X-Requested-With']).toBe('birdcage')
    expect(init.body).toBeUndefined() // the 24 h default is the server's
    expect(confirm).not.toHaveBeenCalled()
  })

  it('while active the same slot reads "end maintenance ▸" (accent) and DELETEs', async () => {
    fetchMock.mockResolvedValue(new Response(null, { status: 204 }))
    const onchanged = vi.fn()
    const { container } = render(CanaryPage, {
      ...props('quiet', (i) => {
        ;(i.page.canary as any).maintenance_until = UNTIL
      }),
      role: 'admin',
      onchanged,
    })
    expect(pill(container, 'mark as maintenance · 24 h')).toBeUndefined()
    const end = pill(container, 'end maintenance ▸')!
    expect(end).toBeTruthy()
    expect(end.classList.contains('quiet')).toBe(false)
    await fireEvent.click(end)
    await vi.waitFor(() => expect(onchanged).toHaveBeenCalled())
    const [url, init] = fetchMock.mock.calls[0]
    expect(url).toBe('/api/admin/canaries/canary-iot/maintenance')
    expect(init.method).toBe('DELETE')
    expect(init.headers['X-Requested-With']).toBe('birdcage')
  })
})

describe('errors', () => {
  const cases: [string, string, string][] = [
    ['run the self-test now ▸', 'Could not queue the self-test. Try again.', 'quiet'],
    ['mark as maintenance · 24 h', 'Could not set maintenance. Try again.', 'quiet'],
  ]
  it.each(cases)('%s failing with 500 says the generic text, never the problem detail', async (label, text, scene) => {
    fetchMock.mockResolvedValue(problem(500))
    const onchanged = vi.fn()
    const { container } = render(CanaryPage, { ...props(scene as SceneName), role: 'admin', onchanged })
    await fireEvent.click(pill(container, label)!)
    await vi.waitFor(() => expect(container.querySelector('p.act-error')).toBeTruthy())
    const err = container.querySelector('p.act-error')!
    expect(err.getAttribute('role')).toBe('alert')
    expect(err.textContent).toBe(text)
    expect(container.textContent).not.toContain('secret internal detail')
    expect(container.querySelector('.acts')!.contains(err) || err.previousElementSibling === container.querySelector('.acts')).toBe(true)
    expect(onchanged).not.toHaveBeenCalled()
  })

  it('end maintenance failing says "Could not end maintenance. Try again."', async () => {
    fetchMock.mockResolvedValue(problem(500))
    const { container } = render(CanaryPage, {
      ...props('quiet', (i) => {
        ;(i.page.canary as any).maintenance_until = UNTIL
      }),
      role: 'admin',
    })
    await fireEvent.click(pill(container, 'end maintenance ▸')!)
    await vi.waitFor(() => expect(container.querySelector('p.act-error')?.textContent).toBe('Could not end maintenance. Try again.'))
  })

  it('a 403 reads "Not allowed with this account."', async () => {
    fetchMock.mockResolvedValue(problem(403))
    const { container } = render(CanaryPage, { ...props('quiet'), role: 'admin' })
    await fireEvent.click(pill(container, 'mark as maintenance · 24 h')!)
    await vi.waitFor(() => expect(container.querySelector('p.act-error')?.textContent).toBe('Not allowed with this account.'))
  })

  it('a 401 goes to onSignedOut', async () => {
    fetchMock.mockResolvedValue(problem(401))
    const signedOut = vi.fn()
    const off = onSignedOut(signedOut)
    const { container } = render(CanaryPage, { ...props('quiet'), role: 'admin' })
    await fireEvent.click(pill(container, 'mark as maintenance · 24 h')!)
    await vi.waitFor(() => expect(signedOut).toHaveBeenCalledTimes(1))
    off()
  })

  it('the message clears on the next click', async () => {
    fetchMock.mockResolvedValueOnce(problem(500)).mockReturnValueOnce(new Promise(() => {}))
    const { container } = render(CanaryPage, { ...props('quiet'), role: 'admin' })
    await fireEvent.click(pill(container, 'mark as maintenance · 24 h')!)
    await vi.waitFor(() => expect(container.querySelector('p.act-error')).toBeTruthy())
    await fireEvent.click(pill(container, 'mark as maintenance · 24 h')!)
    expect(container.querySelector('p.act-error')).toBeNull()
  })
})

describe('how maintenance shows on the page', () => {
  const inMaintenance = (i: ReturnType<typeof sceneInput>) => {
    ;(i.page.canary as any).maintenance_until = UNTIL
  }

  it('a facts row "maintenance" / "until <stamp>", accent, for everyone', () => {
    const { container } = render(CanaryPage, props('quiet', inMaintenance))
    const spans = [...container.querySelectorAll('.facts > span')]
    const i = spans.findIndex((s) => s.textContent === 'maintenance')
    expect(i).toBeGreaterThanOrEqual(0)
    expect(spans[i + 1].textContent).toBe(`until ${STAMP}`)
    expect(spans[i + 1].classList.contains('c')).toBe(true)
  })

  it('no facts row when not in maintenance', () => {
    const { container } = render(CanaryPage, props('quiet'))
    expect([...container.querySelectorAll('.facts > span')].some((s) => s.textContent === 'maintenance')).toBe(false)
  })

  it('the hero sub gains the maintenance sentence', () => {
    const { container } = render(CanaryPage, props('quiet', inMaintenance))
    expect(container.querySelector('.sub')?.textContent).toContain(
      ` In maintenance until ${STAMP}: health warnings are quiet, hits are not.`,
    )
    const plain = render(CanaryPage, props('quiet'))
    expect(plain.container.querySelector('.sub')?.textContent).not.toContain('In maintenance')
  })

  it('a silent canary in maintenance still reads silent (the flag is not a state)', () => {
    const { container } = render(CanaryPage, props('silent', inMaintenance))
    expect(container.querySelector('.hero')?.textContent).toContain('silent')
    expect(container.querySelector('.sub')?.textContent).toContain('In maintenance until')
  })
})
