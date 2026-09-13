import { describe, expect, it } from 'vitest'
import { clusters } from './clusters'

describe('clusters (issue #37)', () => {
  it('keeps far-apart points separate', () => {
    const cx = (ago: number) => 1000 - ago
    const result = clusters([0, 100, 200], cx)
    expect(result).toHaveLength(3)
    expect(result.every((c) => c.count === 1)).toBe(true)
  })

  it('merges points within `gap` px', () => {
    const cx = (ago: number) => 1000 - ago
    // agos 0,1,2 -> x 1000,999,998, all within gap=6 of each other
    const result = clusters([0, 1, 2], cx, 6)
    expect(result).toHaveLength(1)
    expect(result[0]).toMatchObject({ xFrom: 998, xTo: 1000, count: 3 })
  })

  it('is a chain merge -- a run within gap of its neighbour joins even if the ends are further apart than gap', () => {
    const cx = (ago: number) => 1000 - ago
    // x = 1000, 995, 990 -- consecutive gaps are 5 (<=6) but the ends are 10 apart
    const result = clusters([0, 5, 10], cx, 6)
    expect(result).toHaveLength(1)
    expect(result[0].count).toBe(3)
  })

  it('returns an empty list for no hits', () => {
    expect(clusters([], (a) => a)).toEqual([])
  })
})
