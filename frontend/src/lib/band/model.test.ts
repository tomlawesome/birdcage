// Acceptance criterion from issue #37: no label overlaps another label or
// a bump, checked from the placed boxes (not by eye) in each of the three
// fixtures used for the pixel comparison.
import { describe, expect, it } from 'vitest'
import nightFixture from '../../dev/fixtures/night.json'
import poisonerFixture from '../../dev/fixtures/poisoner.json'
import quietFixture from '../../dev/fixtures/quiet.json'
import silentFixture from '../../dev/fixtures/silent.json'
import type { TraceResponse } from '../types'
import { buildBandModel, type PlacedBump } from './model'
import { CHART_TOP } from './placement'

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

// Issue #59 (+ Fable's note 2026-09-24): only high-signal rises keep a text
// label -- credential attempts and poisoner answers -- each joined to its
// rise by a stem. Path, SMB-share and bare-service rises drop their label.
describe('only high-signal rises keep a label (issue #59)', () => {
  const nightLabels = () => buildBandModel(nightFixture.trace as unknown as TraceResponse, 1600).labels

  it('keeps the credential rises and drops the path/SMB ones', () => {
    const l1s = nightLabels().map((l) => l.l1)
    // The named credential rises keep their labels, or -- issue #58 --
    // ride along inside the collapsed banner once the stack they're in
    // runs out of chart (see the dedicated describe block below: night's
    // own four coincident credential rises are exactly that case).
    expect(l1s.some((t) => t.includes('root / root'))).toBe(true)
    expect(l1s).toContain('anonymous / (empty)')
    // ...and every label on the band is a credential or the collapsed
    // count-and-span banner; no path (`/`, `/admin`) or SMB-share (`smb`)
    // label survives.
    expect(l1s.every((t) => t.includes(' / ') || /^\+\d+ more$/.test(t))).toBe(true)
    expect(l1s).not.toContain('smb')
    expect(l1s.some((t) => t.startsWith('/'))).toBe(false)
  })

  it('rewrites the ssh session hit to the service name (fixture fix)', () => {
    // night.json's `session · libssh2` is corrected to `ssh`, what triedFor
    // actually emits; it rides along in the credential rise's joined label.
    const l1s = nightLabels().map((l) => l.l1)
    expect(l1s.some((t) => t.includes('libssh2'))).toBe(false)
    expect(l1s.some((t) => t.includes('root / root') && t.includes('ssh'))).toBe(true)
  })

  it('joins every individually kept label to its rise with a stem -- the collapsed banner has none', () => {
    for (const label of nightLabels()) {
      if (/^\+\d+ more$/.test(label.l1)) {
        expect(label.stem).toMatch(/^M[\d.]+,[\d.]+$/)
      } else {
        expect(label.stem, label.l1).toMatch(/^M[\d.]+,[\d.]+ L/)
      }
    }
  })

  it('keeps a poisoner rise labelled by its bare protocol, not by ` / ` shape', () => {
    const labels = buildBandModel(poisonerFixture.trace as unknown as TraceResponse, 1600).labels
    const poison = labels.find((l) => l.l1 === 'llmnr')
    expect(poison, 'poisoner rise keeps its protocol label').toBeDefined()
    expect(poison!.l1).not.toContain(' / ')
    expect(poison!.stem).toMatch(/^M[\d.]+,[\d.]+ L/)
  })
})

// Issue #58: night.json is the exact reproduction -- four canaries'
// credential rises land within the same last quarter hour and, before
// the fix, stacked their labels straight past the top of the chart and
// into the header/hero above it (root/toor's box measured top=118,
// admin/admin's top=70, against a hero sentence sitting at 94-125px and
// a "tom (admin)" pill at roughly 20-40px). Reproduced at both the
// issue's own 1400px viewport and the pixel-comparison suite's 1600px.
describe('coincident labels collapse instead of leaving the chart (issue #58)', () => {
  it.each([1400, 1600])('every label box stays at or below CHART_TOP, at width %d', (width) => {
    const model = buildBandModel(nightFixture.trace as unknown as TraceResponse, width)
    for (const label of model.labels) {
      expect(label.box.top, label.l1).toBeGreaterThanOrEqual(CHART_TOP)
    }
  })

  it('folds the three rises that would have overflowed into one counted, timed banner', () => {
    const model = buildBandModel(nightFixture.trace as unknown as TraceResponse, 1600)
    const collapsed = model.labels.find((l) => /^\+\d+ more$/.test(l.l1))
    expect(collapsed, 'a collapsed banner label').toBeDefined()
    expect(collapsed!.l1).toBe('+3 more')
    // The span of the three folded rises (mysql root/password & root/
    // (empty), telnet root/toor, telnet root/123456 & admin/admin).
    expect(collapsed!.l2).toBe('21:56–22:04')
    expect(collapsed!.box.top).toBe(CHART_TOP)
  })

  it('never overlaps another label box horizontally at the same row', () => {
    const model = buildBandModel(nightFixture.trace as unknown as TraceResponse, 1400)
    const boxes = model.labels.map((l) => l.box)
    for (let i = 0; i < boxes.length; i++) {
      for (let j = i + 1; j < boxes.length; j++) {
        const overlaps = boxes[i].xFrom < boxes[j].xTo && boxes[i].xTo > boxes[j].xFrom && boxes[i].top < boxes[j].bottom && boxes[i].bottom > boxes[j].top
        expect(overlaps, `label ${i} (${model.labels[i].l1}) overlaps label ${j} (${model.labels[j].l1})`).toBe(false)
      }
    }
  })
})
