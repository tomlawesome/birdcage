// The three duration voices (issue #38), and the hour/day rungs issue
// #45's windows added: token conflict can be 24 h old, an escalated
// stalled rotation is past a day by definition, and neither may read
// "1500 m 0 s". Everything under an hour is pinned unchanged -- that
// range is #38's hand-tuned, pixel-gated copy.
import { describe, expect, it } from 'vitest'
import { agoWords, durationCoarse, durationExact } from './duration'

describe('durationExact -- the tile ladder, two largest units', () => {
  it('under a minute: "9 s"', () => expect(durationExact(9)).toBe('9 s'))
  it('the silent tile is unchanged: "6 m 12 s"', () => expect(durationExact(372)).toBe('6 m 12 s'))
  it('the last pre-hour value keeps the old shape', () => expect(durationExact(3599)).toBe('59 m 59 s'))
  it('an hour turns the ladder: "1 h 0 m", never "60 m 0 s"', () => expect(durationExact(3600)).toBe('1 h 0 m'))
  it('a 20-hour token conflict: "20 h 0 m"', () => expect(durationExact(72000)).toBe('20 h 0 m'))
  it('an escalated stalled rotation: "1 d 2 h", never "1560 m 0 s"', () =>
    expect(durationExact(93600)).toBe('1 d 2 h'))
})

describe('durationCoarse -- the pill, one unit only', () => {
  it('the silent pill is unchanged: "6 m"', () => expect(durationCoarse(372)).toBe('6 m'))
  it('zero stays "0 m", as before', () => expect(durationCoarse(0)).toBe('0 m'))
  it('past an hour: "2 h", never "120 m"', () => expect(durationCoarse(7200)).toBe('2 h'))
  it('past a day: "1 d"', () => expect(durationCoarse(90000)).toBe('1 d'))
})

describe('agoWords -- prose, numbers under ten in words', () => {
  it('"three seconds ago"', () => expect(agoWords(3)).toBe('three seconds ago'))
  it('"six minutes ago"', () => expect(agoWords(372)).toBe('six minutes ago'))
  it('ten and up in digits: "12 minutes ago"', () => expect(agoWords(720)).toBe('12 minutes ago'))
  it('"two hours ago"', () => expect(agoWords(7200)).toBe('two hours ago'))
  it('"20 hours ago"', () => expect(agoWords(72000)).toBe('20 hours ago'))
})
