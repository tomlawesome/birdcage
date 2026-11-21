// #227: the dropped-out event row's maintenance pill. Interface fixed
// here: Events takes `role?: string` and `onchanged?: () => void`.
import { cleanup, fireEvent, render } from '@testing-library/svelte'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import Events from './Events.svelte'
import type { Canary, TraceResponse } from './lib/types'

const trace: TraceResponse = { now: '2026-09-12T22:04:00Z', range: '24h', canaries: [], last_hit: null }

function silent(overrides: Record<string, unknown> = {}): Canary {
  return {
    id: 'canary-lan',
    name: 'canary-lan',
    lane: 'lan',
    ports: 'ssh 22',
    status: 'silent',
    last_heartbeat_at: '2026-09-12T20:00:00Z',
    silent_for_s: 7440,
    hits: 0,
    ...overrides,
  } as Canary
}
const pills = (c: HTMLElement) => [...c.querySelectorAll<HTMLElement>('.row .acts .pill')]

let fetchMock: ReturnType<typeof vi.fn>
beforeEach(() => {
  fetchMock = vi.fn()
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('the dropped-out row pill', () => {
  it('admin: "mark as maintenance · 24 h" button that PUTs and refetches', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ maintenance_until: '2026-09-13T22:00:00Z' }), { status: 200 }))
    const onchanged = vi.fn()
    const { container } = render(Events, { canaries: [silent()], visitors: [], trace, range: '24h', role: 'admin', onchanged })
    const btn = pills(container).find((p) => p.textContent?.trim() === 'mark as maintenance · 24 h') as HTMLButtonElement
    expect(btn?.tagName).toBe('BUTTON')
    await fireEvent.click(btn)
    await vi.waitFor(() => expect(onchanged).toHaveBeenCalled())
    const [url, init] = fetchMock.mock.calls[0]
    expect(url).toBe('/api/admin/canaries/canary-lan/maintenance')
    expect(init.method).toBe('PUT')
    expect(init.headers['X-Requested-With']).toBe('birdcage')
  })

  it('in maintenance the row stays and its pill becomes "end maintenance ▸" (DELETE)', async () => {
    fetchMock.mockResolvedValue(new Response(null, { status: 204 }))
    const { container } = render(Events, {
      canaries: [silent({ maintenance_until: '2026-09-13T22:00:00Z' })],
      visitors: [],
      trace,
      range: '24h',
      role: 'admin',
    })
    expect(container.querySelectorAll('.row')).toHaveLength(1)
    const texts = pills(container).map((p) => p.textContent?.trim())
    expect(texts).toContain('end maintenance ▸')
    expect(texts).not.toContain('mark as maintenance · 24 h')
    await fireEvent.click(pills(container).find((p) => p.textContent?.trim() === 'end maintenance ▸')!)
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalled())
    expect(fetchMock.mock.calls[0][1].method).toBe('DELETE')
  })

  it.each(['viewer', undefined])('role %s: no maintenance pill', (role) => {
    const { container } = render(Events, { canaries: [silent()], visitors: [], trace, range: '24h', role })
    expect(container.textContent).not.toContain('maintenance')
  })
})
