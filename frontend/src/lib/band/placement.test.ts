// Issue #58: placeRises is the pure layout function underneath the trace
// -- positions and label text in, rows of bumps and labels out, no DOM
// involved. These fixtures build synthetic rises directly (rather than
// going through a fixture trace, as model.test.ts's acceptance suite
// does) so the collapse rule is exercised on inputs chosen to hit it
// exactly, not just on whatever the night fixture happens to produce.
import { describe, expect, it } from 'vitest'
import { CHART_TOP, placeRises, type Rise } from './placement'

const X0 = 190
const X1 = 1520
const BAND_TOP = 290

/** A labelled rise sitting on its own canary line, `n` lanes down from
 * the top one (PITCH=12 in model.ts; near enough here that the exact
 * constant doesn't matter -- what matters is that four such rises,
 * close together in x, collide vertically the way four canaries'
 * coincident credential rises do). */
function rise(xFrom: number, lane: number, l1: string, atFrom: number, atTo = atFrom): Rise {
  return { xFrom, xTo: xFrom + 4, y: BAND_TOP + lane * 12, kind: 'repeat', l1, l2: 'l2', labelled: true, atFrom, atTo }
}

describe('placeRises: stacking (issue #37, unchanged by #58)', () => {
  it('a single labelled rise gets its own label, clear of the chart top', () => {
    const layout = placeRises([rise(800, 0, 'a / a', 0)], X0, X1, BAND_TOP)
    expect(layout.labels).toHaveLength(1)
    expect(layout.labels[0].l1).toBe('a / a')
    expect(layout.labels[0].box.top).toBeGreaterThan(CHART_TOP)
  })

  it('two rises far apart in x each get their own label, unstacked', () => {
    const layout = placeRises([rise(300, 0, 'a / a', 0), rise(1200, 0, 'b / b', 1)], X0, X1, BAND_TOP)
    expect(layout.labels.map((l) => l.l1).sort()).toEqual(['a / a', 'b / b'])
  })

  it('two rises close together stack -- the second sits higher, neither crosses the chart top', () => {
    const layout = placeRises([rise(800, 0, 'a / a', 0), rise(800, 0, 'b / b', 1)], X0, X1, BAND_TOP)
    expect(layout.labels).toHaveLength(2)
    const [first, second] = [...layout.labels].sort((a, b) => b.box.top - a.box.top)
    expect(first.box.top).toBeGreaterThan(second.box.top)
    expect(second.box.top).toBeGreaterThanOrEqual(CHART_TOP)
  })
})

describe('placeRises: the collapse rule (issue #58)', () => {
  it('folds a stack that would cross the chart top into one banner, earlier labels in the stack untouched', () => {
    // Four rises at nearly the same x, on four different lanes -- the
    // same shape as four canaries' coincident credential hits. The
    // first has room to stack normally; by the third or fourth, growing
    // further would cross CHART_TOP.
    const rises = [
      rise(800, 0, 'a / a', 1000),
      rise(806, 1, 'b / b', 2000),
      rise(812, 2, 'c / c', 3000),
      rise(818, 3, 'd / d', 4000),
    ]
    const layout = placeRises(rises, X0, X1, BAND_TOP)

    // Nothing ever leaves the chart box.
    for (const label of layout.labels) expect(label.box.top).toBeGreaterThanOrEqual(CHART_TOP)

    // At least one individual label survives (the stack "stays as it is
    // while it fits"), and the rest are represented by exactly one
    // collapsed banner, not silently dropped.
    const individual = layout.labels.filter((l) => !l.l1.startsWith('+'))
    const collapsed = layout.labels.filter((l) => l.l1.startsWith('+'))
    expect(individual.length).toBeGreaterThan(0)
    expect(collapsed).toHaveLength(1)
    expect(individual.length + Number(collapsed[0].l1.match(/^\+(\d+) more$/)![1])).toBe(rises.length)

    // The collapsed banner sits exactly on the chart's top edge and
    // carries the earliest-to-latest span of what it folded in.
    expect(collapsed[0].box.top).toBe(CHART_TOP)
    expect(collapsed[0].l2).toMatch(/^\d\d:\d\d\u2013\d\d:\d\d$/)

    // Every rise still draws a bump -- the shape stays even once its
    // words move into the banner.
    expect(layout.bumps).toHaveLength(rises.length)
  })

  it('a second, unrelated crowd elsewhere on the same chart collapses on its own, not merged with the first', () => {
    const first = [rise(300, 0, 'a / a', 1000), rise(306, 1, 'b / b', 2000), rise(312, 2, 'c / c', 3000), rise(318, 3, 'd / d', 4000)]
    const second = [rise(1300, 0, 'e / e', 5000), rise(1306, 1, 'f / f', 6000), rise(1312, 2, 'g / g', 7000), rise(1318, 3, 'h / h', 8000)]
    const layout = placeRises([...first, ...second], X0, X1, BAND_TOP)

    const collapsed = layout.labels.filter((l) => l.l1.startsWith('+'))
    expect(collapsed).toHaveLength(2)
    for (const label of layout.labels) expect(label.box.top).toBeGreaterThanOrEqual(CHART_TOP)
    // The two banners don't overlap each other.
    const [a, b] = collapsed
    const overlap = a.box.xFrom < b.box.xTo && a.box.xTo > b.box.xFrom
    expect(overlap).toBe(false)
  })

  it('labels that would overlap horizontally at the same row join the cluster rather than overprinting', () => {
    // Same x, different lanes, close enough that their label boxes
    // would overlap horizontally once stacked to the same row.
    const rises = [rise(800, 0, 'a / a', 1000), rise(801, 1, 'b / b', 2000), rise(802, 2, 'c / c', 3000)]
    const layout = placeRises(rises, X0, X1, BAND_TOP)
    const boxes = layout.labels.map((l) => l.box)
    for (let i = 0; i < boxes.length; i++) {
      for (let j = i + 1; j < boxes.length; j++) {
        const overlaps = boxes[i].xFrom < boxes[j].xTo && boxes[i].xTo > boxes[j].xFrom && boxes[i].top < boxes[j].bottom && boxes[i].bottom > boxes[j].top
        expect(overlaps).toBe(false)
      }
    }
  })
})
