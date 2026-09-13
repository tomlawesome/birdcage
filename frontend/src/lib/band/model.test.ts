// Acceptance criterion from issue #37: no label overlaps another label or
// a bump, checked from the placed boxes (not by eye) in each of the three
// fixtures used for the pixel comparison.
import { describe, expect, it } from 'vitest'
import nightFixture from '../../dev/fixtures/night.json'
import quietFixture from '../../dev/fixtures/quiet.json'
import silentFixture from '../../dev/fixtures/silent.json'
import type { TraceResponse } from '../types'
import { buildBandModel, type PlacedBump } from './model'

interface Box {
  xFrom: number
  xTo: number
  top: number
  bottom: number
}

function overlaps(a: Box, b: Box): boolean {
  return a.xFrom < b.xTo && a.xTo > b.xFrom && a.top < b.bottom && a.bottom > b.top
}

function bumpBox(b: PlacedBump, x1: number): Box {
  return { xFrom: b.xFrom - b.bw, xTo: Math.min(b.xTo + b.bw, x1), top: b.y - b.h, bottom: b.y }
}

const FIXTURES: Array<[string, TraceResponse]> = [
  ['quiet', quietFixture.trace as unknown as TraceResponse],
  ['silent', silentFixture.trace as unknown as TraceResponse],
  ['night', nightFixture.trace as unknown as TraceResponse],
]

describe('label placement has no overlaps (issue #37 acceptance)', () => {
  for (const [scene, trace] of FIXTURES) {
    it(`${scene}: no label box overlaps another label box`, () => {
      const model = buildBandModel(trace, 1600)
      const boxes = model.labels.map((l) => l.box)
      for (let i = 0; i < boxes.length; i++) {
        for (let j = i + 1; j < boxes.length; j++) {
          expect(overlaps(boxes[i], boxes[j]), `label ${i} overlaps label ${j}`).toBe(false)
        }
      }
    })

    it(`${scene}: no label box overlaps a bump`, () => {
      const model = buildBandModel(trace, 1600)
      const labelBoxes = model.labels.map((l) => l.box)
      const bumpBoxes = model.bumps.map((b) => bumpBox(b, model.x1))
      for (let i = 0; i < labelBoxes.length; i++) {
        for (let j = 0; j < bumpBoxes.length; j++) {
          expect(overlaps(labelBoxes[i], bumpBoxes[j]), `label ${i} overlaps bump ${j}`).toBe(false)
        }
      }
    })
  }

  it('quiet and silent have no hits, so no labels or bumps at all', () => {
    for (const [scene, trace] of FIXTURES.slice(0, 2)) {
      const model = buildBandModel(trace, 1600)
      expect(model.labels, scene).toHaveLength(0)
      expect(model.bumps, scene).toHaveLength(0)
    }
  })

  it('night has labelled rises for each visitor group', () => {
    const model = buildBandModel(nightFixture.trace as unknown as TraceResponse, 1600)
    expect(model.labels.length).toBeGreaterThan(0)
  })
})
