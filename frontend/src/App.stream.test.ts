// Issue #44: the dashboard's server-sent-events subscription. These
// tests cover the frontend half of the "Done when" list -- the backend
// half (a hit written by the ingest path arrives within a second) is
// proven in internal/api/stream_test.go against the real Go handler.
// jsdom (the test environment) has no EventSource implementation at all
// (`typeof EventSource === 'undefined'`, checked directly), which is
// itself a useful stand-in for "the stream is unavailable" -- exercised
// explicitly below -- so a mock EventSource is installed only in the
// tests that need one.
import { render } from '@testing-library/svelte'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App.svelte'
// A structurally-real fixture (already used to drive dev-mode rendering
// and the pixel-gate comparisons), reused here instead of a hand-rolled
// shape -- App.svelte's descendants (Band, Tiles, Events) need a fully
// valid trace/canaries/visitors shape to render without crashing, which
// is incidental to what these tests actually check.
import quietFixture from './dev/fixtures/quiet.json'

// A minimal EventSource stand-in: no real connection, just enough
// surface (onmessage, close()) for App.svelte's subscription to drive.
// instances lets a test reach into whichever App.svelte constructed.
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

function stubSuccessfulFetch() {
  vi.stubGlobal(
    'fetch',
    vi.fn((path: string) => {
      if (path.includes('/api/canaries')) {
        return Promise.resolve({ ok: true, json: async () => quietFixture.canaries })
      }
      if (path.includes('/api/visitors')) {
        return Promise.resolve({ ok: true, json: async () => quietFixture.visitors })
      }
      if (path.includes('/api/trace')) {
        return Promise.resolve({ ok: true, json: async () => quietFixture.trace })
      }
      return Promise.reject(new Error(`unexpected fetch: ${path}`))
    }),
  )
}

describe('server-sent updates (#44)', () => {
  beforeEach(() => {
    FakeEventSource.instances = []
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    vi.useRealTimers()
  })

  it('with EventSource unavailable, the dashboard behaves exactly as it does today (poll still fires)', async () => {
    // No stubGlobal('EventSource', ...) here: jsdom already has none, so
    // this exercises the real "stream disabled entirely" case the issue
    // requires, not a simulation of it.
    expect(typeof EventSource).toBe('undefined')

    vi.useFakeTimers()
    stubSuccessfulFetch()
    render(App)
    await vi.advanceTimersByTimeAsync(0) // let the initial load() settle

    const callsAfterMount = (fetch as unknown as ReturnType<typeof vi.fn>).mock.calls.length
    expect(callsAfterMount).toBeGreaterThan(0)

    await vi.advanceTimersByTimeAsync(30_000) // REFRESH_MS, App.svelte:37
    const callsAfterPoll = (fetch as unknown as ReturnType<typeof vi.fn>).mock.calls.length
    expect(callsAfterPoll).toBeGreaterThan(callsAfterMount)
  })

  it('a pushed alert triggers an immediate refetch, merged through the existing loader', async () => {
    vi.stubGlobal('EventSource', FakeEventSource)
    vi.useFakeTimers()
    stubSuccessfulFetch()

    render(App)
    await vi.advanceTimersByTimeAsync(0) // initial load()

    expect(FakeEventSource.instances).toHaveLength(1)
    expect(FakeEventSource.instances[0].url).toBe('/api/stream')

    const callsBeforePush = (fetch as unknown as ReturnType<typeof vi.fn>).mock.calls.length

    // Simulate the server pushing a stored alert -- the payload itself
    // is never parsed (App.svelte's onmessage just re-triggers the same
    // load() the poll uses), so any message is enough.
    FakeEventSource.instances[0].onmessage?.({ data: JSON.stringify(quietFixture.canaries.canaries[0]) })
    await vi.advanceTimersByTimeAsync(0)

    const callsAfterPush = (fetch as unknown as ReturnType<typeof vi.fn>).mock.calls.length
    expect(callsAfterPush).toBeGreaterThan(callsBeforePush)
  })

  it('killing the stream leaves the poll updating on its own', async () => {
    vi.stubGlobal('EventSource', FakeEventSource)
    vi.useFakeTimers()
    stubSuccessfulFetch()

    render(App)
    await vi.advanceTimersByTimeAsync(0)

    // "Kill" the stream the way a dropped connection would surface to
    // this code: no more messages ever arrive. App.svelte never notices
    // or reacts -- the poll interval it already owns is untouched by
    // anything the stream does or doesn't do.
    const callsBeforeSilence = (fetch as unknown as ReturnType<typeof vi.fn>).mock.calls.length
    await vi.advanceTimersByTimeAsync(30_000)
    const callsAfterSilence = (fetch as unknown as ReturnType<typeof vi.fn>).mock.calls.length

    expect(callsAfterSilence).toBeGreaterThan(callsBeforeSilence)
  })
})
