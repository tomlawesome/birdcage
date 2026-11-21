// #227: after a refused self-test request the pill is usable again.
import { cleanup, fireEvent, render } from '@testing-library/svelte'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import CanaryPage from './CanaryPage.svelte'
import { sceneInput } from './lib/canary/fixtures'

function props() {
  const i = sceneInput('quiet')
  return { page: i.page, trace: i.trace, visitors: i.visitors, history: i.history, runs: null, range: '14d' as const }
}
const prob = (status: number) =>
  new Response(JSON.stringify({ type: 'about:blank', title: 'x', status, detail: 'internal detail' }), {
    status,
    headers: { 'Content-Type': 'application/problem+json' },
  })
let fetchMock: ReturnType<typeof vi.fn>
beforeEach(() => {
  fetchMock = vi.fn()
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})
const pill = (c: HTMLElement) => [...c.querySelectorAll<HTMLButtonElement>('.acts button.pill')].find((b) => /^(run the self-test now ▸|self-test queued…)$/.test(b.textContent?.trim() ?? ''))!

describe('the self-test pill after a refused request', () => {
  it.each([
    ['409', () => prob(409)],
    ['500', () => prob(500)],
    ['a network error', () => Promise.reject(new TypeError('Failed to fetch'))],
  ])('%s: enabled again, original wording, error shown, a second click sends a request', async (_n, reply) => {
    fetchMock.mockImplementation(() => Promise.resolve().then(reply))
    const onchanged = vi.fn()
    const { container } = render(CanaryPage, { ...props(), role: 'admin', onchanged })
    await fireEvent.click(pill(container))
    await vi.waitFor(() => expect(container.querySelector('p.act-error')?.textContent).toBe('Could not queue the self-test. Try again.'))
    expect(pill(container).textContent?.trim()).toBe('run the self-test now ▸')
    expect(pill(container).disabled).toBe(false)
    expect(onchanged).not.toHaveBeenCalled()
    await fireEvent.click(pill(container))
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2))
  })
})
