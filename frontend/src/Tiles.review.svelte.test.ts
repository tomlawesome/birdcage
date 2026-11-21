// #227 review findings: hit lines win over maintenance on the tile; a
// write in flight disables its pill.
import { cleanup, fireEvent, render } from '@testing-library/svelte'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import Tiles from './Tiles.svelte'
import Events from './Events.svelte'
import type { Canary, TraceResponse } from './lib/types'

const UNTIL = '2026-09-13T22:00:00Z'
const c = (o: Record<string, unknown> = {}) =>
  ({ id: 'canary-iot', name: 'canary-iot', lane: 'iot', ports: 'ssh 22', status: 'ok', last_heartbeat_at: '2026-09-12T22:00:00Z', hits: 0, ...o }) as Canary
let fetchMock: ReturnType<typeof vi.fn>
beforeEach(() => {
  fetchMock = vi.fn()
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('hit lines on a tile in maintenance', () => {
  it('get no maintenance prefix, and the line still reads as the hit', () => {
    const trace: TraceResponse = {
      now: '2026-09-12T22:04:00Z',
      range: '24h',
      canaries: [{ id: 'canary-iot', hits: [{ at: '2026-09-12T22:01:00Z', kind: 'inside', service: 'ssh' }] }] as any,
      last_hit: null,
    }
    const { container } = render(Tiles, { canaries: [c({ hits: 1, maintenance_until: UNTIL })], trace, range: '24h' })
    expect(container.textContent).not.toContain('◌ maintenance until')
    expect(container.textContent).toContain('from inside')
  })
})

describe('a write in flight on the tile and the event row', () => {
  const trace: TraceResponse = { now: '2026-09-12T22:04:00Z', range: '24h', canaries: [], last_hit: null }
  const silent = c({ id: 'canary-lan', name: 'canary-lan', lane: 'lan', status: 'silent', silent_for_s: 7200, last_heartbeat_at: '2026-09-12T20:00:00Z' })

  it.each([
    ['tile', (p: any) => render(Tiles, { canaries: [silent], trace, range: '24h', ...p }), '.tile .acts button.pill'],
    ['event row', (p: any) => render(Events, { canaries: [silent], visitors: [], trace, range: '24h', ...p }), '.row .acts button.pill'],
  ])('%s: disabled while in flight, a double click sends one request', async (_n, mount, sel) => {
    let release!: (r: Response) => void
    fetchMock.mockReturnValue(new Promise<Response>((r) => (release = r)))
    const { container } = mount({ role: 'admin', onchanged: vi.fn() })
    const b = container.querySelector<HTMLButtonElement>(sel)!
    await fireEvent.click(b)
    await vi.waitFor(() => expect(b.disabled).toBe(true))
    await fireEvent.click(b)
    expect(fetchMock).toHaveBeenCalledTimes(1)
    release(new Response(JSON.stringify({ maintenance_until: UNTIL }), { status: 200 }))
    await vi.waitFor(() => expect(b.disabled).toBe(false))
  })
})
