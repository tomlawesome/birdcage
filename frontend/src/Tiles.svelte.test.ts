// Tiles.svelte's own decision: which outline class (critical/degraded)
// a tile's outer div gets for each CanaryStatus. The status line text
// itself is computeTileStatus's job, already covered elsewhere.
import { render } from '@testing-library/svelte'
import { describe, expect, it } from 'vitest'
import Tiles from './Tiles.svelte'
import type { Canary, TraceResponse } from './lib/types'

const trace: TraceResponse = { now: '2026-09-12T22:04:00Z', range: '24h', canaries: [], last_hit: null }

function canary(overrides: Partial<Canary> = {}): Canary {
  return {
    id: 'canary-iot',
    name: 'canary-iot',
    lane: 'iot',
    ports: 'ssh 22',
    status: 'ok',
    last_heartbeat_at: '2026-09-12T22:00:00Z',
    hits: 0,
    ...overrides,
  }
}

describe('Tiles.svelte: outline class per status', () => {
  it('opencanary_down gets the critical outline, same tier as not_delivering', () => {
    const { container } = render(Tiles, { canaries: [canary({ status: 'opencanary_down' })], trace, range: '24h' })
    const tile = container.querySelector('.tile')
    expect(tile?.classList.contains('critical')).toBe(true)
  })

  it('db_stale gets the degraded outline, same tier as rotation_stalled', () => {
    const { container } = render(Tiles, { canaries: [canary({ status: 'db_stale' })], trace, range: '24h' })
    const tile = container.querySelector('.tile')
    expect(tile?.classList.contains('degraded')).toBe(true)
  })
})
