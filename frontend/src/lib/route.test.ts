import { describe, expect, it } from 'vitest'
import { canaryHref, cageHref, parseRoute } from './route'

describe('parseRoute', () => {
  it('reads a canary page out of the hash', () => {
    expect(parseRoute('#/canaries/canary-iot')).toEqual({ name: 'canary', id: 'canary-iot' })
  })

  it('treats an empty, bare or unknown hash as the cage', () => {
    expect(parseRoute('')).toEqual({ name: 'cage' })
    expect(parseRoute('#/')).toEqual({ name: 'cage' })
    expect(parseRoute('#/visitors')).toEqual({ name: 'cage' })
    expect(parseRoute('#/canaries/')).toEqual({ name: 'cage' })
  })

  it('refuses a deeper path rather than reading the first segment as an id', () => {
    expect(parseRoute('#/canaries/canary-iot/raw')).toEqual({ name: 'cage' })
  })

  it('round-trips an id that needs escaping', () => {
    const id = 'canary/iot #1'
    expect(parseRoute(canaryHref(id))).toEqual({ name: 'canary', id })
  })

  it('cageHref is a real address, so leaving a canary page fires a navigation', () => {
    expect(cageHref).toBe('#/')
    expect(parseRoute(cageHref)).toEqual({ name: 'cage' })
  })
})
