import { describe, expect, it } from 'vitest'
import { initialLoaderState, onFetchError, onFetchSuccess, type LoaderData } from './loader'

const data: LoaderData = {
  canaries: [],
  visitors: [],
  trace: { now: '2026-09-12T22:04:31Z', range: '14d', canaries: [], last_hit: null },
}

const otherData: LoaderData = {
  ...data,
  trace: { ...data.trace, now: '2026-09-12T22:05:01Z' },
}

describe('loader state machine (issue #39)', () => {
  it('starts in loading with no data', () => {
    expect(initialLoaderState).toEqual({ phase: 'loading', data: null })
  })

  it('a first successful fetch moves to ready', () => {
    const s = onFetchSuccess(data)
    expect(s).toEqual({ phase: 'ready', data })
  })

  it('a failed first fetch (no earlier data) moves to error, not stale', () => {
    const s = onFetchError(initialLoaderState)
    expect(s).toEqual({ phase: 'error', data: null })
  })

  it('a failed refetch after a success keeps the old data and moves to stale', () => {
    const ready = onFetchSuccess(data)
    const s = onFetchError(ready)
    expect(s).toEqual({ phase: 'stale', data })
  })

  it('a successful refetch after stale returns to ready with the new data', () => {
    const stale = onFetchError(onFetchSuccess(data))
    const s = onFetchSuccess(otherData)
    expect(s).toEqual({ phase: 'ready', data: otherData })
    expect(stale.phase).toBe('stale')
  })

  it('repeated failures stay stale with the same last-good data, never clobbered', () => {
    let s = onFetchError(onFetchSuccess(data))
    s = onFetchError(s)
    s = onFetchError(s)
    expect(s).toEqual({ phase: 'stale', data })
  })
})
