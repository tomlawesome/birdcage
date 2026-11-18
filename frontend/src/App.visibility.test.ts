// Issue #190: pause background checks while the tab is hidden. The poll
// (30 s) stops and /api/stream is closed on `hidden`; `visible` runs one
// refresh at once, restarts the poll from then and reopens the stream.
import { render } from '@testing-library/svelte'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App.svelte'
import quietFixture from './dev/fixtures/quiet.json'

class FakeEventSource {
  static instances: FakeEventSource[] = []
  onmessage: ((ev: { data: string }) => void) | null = null
  closed = false
  url: string
  constructor(url: string) {
    this.url = url
    FakeEventSource.instances.push(this)
  }
  close() {
    this.closed = true
  }
}

const signedIn = { setupRequired: false, ssoAvailable: false, authenticated: true, hasLocalPassword: true, ssoConnected: false, mustChangePassword: false, mustEnrolSecondFactor: false, mustEnrolPasskey: false, hasTOTP: true, username: 'avery', role: 'admin' }
const POLL_MS = 30_000

let state: 'visible' | 'hidden' = 'visible'
let urls: string[] = []

function stubFetch() {
  urls = []
  vi.stubGlobal(
    'fetch',
    vi.fn((path: string) => {
      urls.push(path)
      if (path === '/api/auth/session') {
        return Promise.resolve({ ok: true, json: async () => signedIn })
      }
      if (path.includes('/api/canaries')) return Promise.resolve({ ok: true, json: async () => quietFixture.canaries })
      if (path.includes('/api/visitors')) return Promise.resolve({ ok: true, json: async () => quietFixture.visitors })
      if (path.includes('/api/trace')) return Promise.resolve({ ok: true, json: async () => quietFixture.trace })
      return Promise.reject(new Error(`unexpected fetch: ${path}`))
    }),
  )
}

// Background-check requests: everything except the session read.
const polls = () => urls.filter((u) => u !== '/api/auth/session').length
const openStreams = () => FakeEventSource.instances.filter((s) => !s.closed).length

function setVisibility(next: 'visible' | 'hidden') {
  state = next
  document.dispatchEvent(new Event('visibilitychange'))
}

async function mount(initial: 'visible' | 'hidden') {
  state = initial
  stubFetch()
  render(App)
  await vi.advanceTimersByTimeAsync(0)
}

describe('hidden tab pauses background checks (#190)', () => {
  beforeEach(() => {
    FakeEventSource.instances = []
    vi.stubGlobal('EventSource', FakeEventSource)
    vi.useFakeTimers()
    Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => state })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    vi.useRealTimers()
    delete (document as unknown as Record<string, unknown>).visibilityState
  })

  it('visible the whole time: polls every 30 s and keeps the stream open', async () => {
    await mount('visible')
    expect(openStreams()).toBe(1)
    const before = polls()
    expect(before).toBeGreaterThan(0)
    await vi.advanceTimersByTimeAsync(POLL_MS)
    const after1 = polls()
    expect(after1).toBeGreaterThan(before)
    await vi.advanceTimersByTimeAsync(POLL_MS)
    expect(polls()).toBeGreaterThan(after1)
    expect(openStreams()).toBe(1)
  })

  it('hidden for several poll intervals: no poll requests and the stream is closed', async () => {
    await mount('visible')
    setVisibility('hidden')
    await vi.advanceTimersByTimeAsync(0)
    const atHide = polls()
    await vi.advanceTimersByTimeAsync(POLL_MS * 5)
    expect(polls()).toBe(atHide)
    expect(openStreams()).toBe(0)
  })

  it('shown again: one refresh at once, the next poll 30 s later, stream open again', async () => {
    await mount('visible')
    setVisibility('hidden')
    await vi.advanceTimersByTimeAsync(POLL_MS * 5)
    const atShow = polls()
    setVisibility('visible')
    await vi.advanceTimersByTimeAsync(0)
    const afterShow = polls()
    expect(afterShow).toBeGreaterThan(atShow)
    const oneLoad = afterShow - atShow
    expect(openStreams()).toBe(1)
    // No extra poll before 30 s from showing, then exactly one more load.
    await vi.advanceTimersByTimeAsync(POLL_MS - 1)
    expect(polls()).toBe(afterShow)
    await vi.advanceTimersByTimeAsync(1)
    expect(polls() - afterShow).toBe(oneLoad)
  })

  it('a tab that starts hidden makes no poll or stream until shown', async () => {
    await mount('hidden')
    expect(polls()).toBe(0)
    expect(openStreams()).toBe(0)
    await vi.advanceTimersByTimeAsync(POLL_MS * 4)
    expect(polls()).toBe(0)
    expect(openStreams()).toBe(0)
    setVisibility('visible')
    await vi.advanceTimersByTimeAsync(0)
    expect(polls()).toBeGreaterThan(0)
    expect(openStreams()).toBe(1)
  })
})
