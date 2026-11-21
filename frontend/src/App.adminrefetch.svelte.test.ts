// #227 review finding: a write's refetch is not lost when a load is
// already in flight -- after the write's 2xx a fresh load runs once the
// in-flight one has finished.
import { render, fireEvent } from '@testing-library/svelte'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App.svelte'
import silentFixture from './dev/fixtures/silent.json'

class FakeEventSource {
  onmessage: unknown = null
  close() {}
}
const admin = { setupRequired: false, ssoAvailable: false, authenticated: true, hasLocalPassword: true, ssoConnected: false, mustChangePassword: false, mustEnrolSecondFactor: false, mustEnrolPasskey: false, hasTOTP: true, username: 'avery', role: 'admin' }

describe('a write during an in-flight load', () => {
  let urls: string[] = []
  let hold = false
  let releaseHeld: (() => void) | null = null
  beforeEach(() => {
    urls = []
    vi.stubGlobal('EventSource', FakeEventSource)
    vi.useFakeTimers()
    vi.stubGlobal(
      'fetch',
      vi.fn((path: string, init?: RequestInit) => {
        urls.push(`${init?.method ?? 'GET'} ${path}`)
        if (init?.method === 'PUT') return Promise.resolve(new Response(JSON.stringify({ maintenance_until: '2026-09-07T00:00:00Z' }), { status: 200 }))
        if (path === '/api/auth/session') return Promise.resolve({ ok: true, json: async () => admin })
        if (path.includes('/api/canaries')) {
          const body = { ok: true, json: async () => silentFixture.canaries }
          if (hold) return new Promise((r) => (releaseHeld = () => r(body)))
          return Promise.resolve(body)
        }
        if (path.includes('/api/visitors')) return Promise.resolve({ ok: true, json: async () => silentFixture.visitors })
        if (path.includes('/api/trace')) return Promise.resolve({ ok: true, json: async () => silentFixture.trace })
        return Promise.reject(new Error(`unexpected fetch: ${path}`))
      }),
    )
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    vi.useRealTimers()
  })

  it('loads again after the held load finishes', async () => {
    const { container } = render(App)
    await vi.advanceTimersByTimeAsync(0)
    const loads = () => urls.filter((u) => u.startsWith('GET /api/canaries')).length
    expect(loads()).toBe(1)
    const pill = container.querySelector<HTMLButtonElement>('.tile .acts button.pill')!
    expect(pill).toBeTruthy()

    hold = true
    await vi.advanceTimersByTimeAsync(30_000) // the poll starts a load that stays in flight
    expect(loads()).toBe(2)
    await fireEvent.click(pill)
    await vi.advanceTimersByTimeAsync(0)
    expect(urls.some((u) => u.startsWith('PUT /api/admin/canaries/'))).toBe(true)

    hold = false
    releaseHeld!()
    await vi.advanceTimersByTimeAsync(0)
    expect(loads()).toBe(3)
  })
})
