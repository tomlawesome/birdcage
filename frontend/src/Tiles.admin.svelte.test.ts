// #227: maintenance on the cage tile, and the tile's own maintenance
// pill. Interface fixed here: Tiles takes `role?: string` and
// `onchanged?: () => void`, like CanaryPage.
import { cleanup, fireEvent, render } from '@testing-library/svelte'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import Tiles from './Tiles.svelte'
import type { Canary, TraceResponse } from './lib/types'

const trace: TraceResponse = { now: '2026-09-12T22:04:00Z', range: '24h', canaries: [], last_hit: null }
const UNTIL = '2026-09-13T22:00:00Z'
const STAMP = 'sun 13 sep 22:00'

function canary(overrides: Record<string, unknown> = {}): Canary {
  return {
    id: 'canary-iot',
    name: 'canary-iot',
    lane: 'iot',
    ports: 'ssh 22',
    status: 'ok',
    last_heartbeat_at: '2026-09-12T22:00:00Z',
    hits: 0,
    ...overrides,
  } as Canary
}
const lines = (container: HTMLElement) => [...container.querySelectorAll('.tile .wn, .tile .al, .tile .off')].map((e) => e.textContent ?? '')

let fetchMock: ReturnType<typeof vi.fn>
beforeEach(() => {
  fetchMock = vi.fn()
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('the cage tile in maintenance', () => {
  it('first line is "◌ maintenance until <stamp> · <underlying line>", class wn, tile degraded', () => {
    const { container } = render(Tiles, {
      canaries: [canary({ status: 'silent', silent_for_s: 7200, maintenance_until: UNTIL })],
      trace,
      range: '24h',
    })
    const line = [...container.querySelectorAll('.tile .wn')].find((e) => e.textContent?.startsWith('◌ maintenance until'))!
    expect(line).toBeTruthy()
    expect(line.textContent).toContain(`◌ maintenance until ${STAMP} · ○ silent`)
    expect(container.querySelector('.tile')!.classList.contains('degraded')).toBe(true)
  })

  it.each([
    ['hits_merged', { event_id_collisions: 2 }, 'hits merged'],
    ['token_conflict', { token_conflict_for_s: 60 }, 'token conflict'],
    ['not_delivering', {}, 'not delivering'],
  ])('a %s line wins over maintenance', (status, extra, words) => {
    const { container } = render(Tiles, {
      canaries: [canary({ status, maintenance_until: UNTIL, ...extra })],
      trace,
      range: '24h',
    })
    expect(container.textContent).toContain(words)
    expect(container.textContent).not.toContain('◌ maintenance until')
  })

  it('no maintenance line without maintenance_until', () => {
    const { container } = render(Tiles, { canaries: [canary({ status: 'silent', silent_for_s: 7200 })], trace, range: '24h' })
    expect(container.textContent).not.toContain('◌ maintenance')
    expect(lines(container).length).toBeGreaterThan(0)
  })
})

describe('the tile pill', () => {
  it('admin on a silent tile: "open" link plus one "mark as maintenance · 24 h" button that PUTs', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ maintenance_until: UNTIL }), { status: 200 }))
    const onchanged = vi.fn()
    const { container } = render(Tiles, {
      canaries: [canary({ status: 'silent', silent_for_s: 7200 })],
      trace,
      range: '24h',
      role: 'admin',
      onchanged,
    })
    const pills = [...container.querySelectorAll('.tile .acts .pill')]
    expect(pills.map((p) => p.textContent?.trim())).toEqual(['open canary-iot ▸', 'mark as maintenance · 24 h'])
    const btn = pills[1] as HTMLButtonElement
    expect(btn.tagName).toBe('BUTTON')
    await fireEvent.click(btn)
    await vi.waitFor(() => expect(onchanged).toHaveBeenCalled())
    const [url, init] = fetchMock.mock.calls[0]
    expect(url).toBe('/api/admin/canaries/canary-iot/maintenance')
    expect(init.method).toBe('PUT')
    expect(init.headers['X-Requested-With']).toBe('birdcage')
  })

  it('in maintenance the tile pill reads "end maintenance ▸" and DELETEs', async () => {
    fetchMock.mockResolvedValue(new Response(null, { status: 204 }))
    const { container } = render(Tiles, {
      canaries: [canary({ status: 'silent', silent_for_s: 7200, maintenance_until: UNTIL })],
      trace,
      range: '24h',
      role: 'admin',
    })
    const btn = [...container.querySelectorAll<HTMLButtonElement>('.tile .acts button.pill')].find((b) => b.textContent?.trim() === 'end maintenance ▸')!
    expect(btn).toBeTruthy()
    await fireEvent.click(btn)
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalled())
    expect(fetchMock.mock.calls[0][1].method).toBe('DELETE')
  })

  it('a non-admin never gets the maintenance pill', () => {
    const { container } = render(Tiles, {
      canaries: [canary({ status: 'silent', silent_for_s: 7200 })],
      trace,
      range: '24h',
      role: 'viewer',
    })
    expect(container.querySelector('.tile .acts button')).toBeNull()
    expect(container.textContent).not.toContain('mark as maintenance')
  })
})
