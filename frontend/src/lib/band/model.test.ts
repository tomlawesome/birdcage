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
    // The named credential rises keep their labels...
    expect(l1s.some((t) => t.includes('root / root'))).toBe(true)
    expect(l1s).toContain('root / toor')
    expect(l1s).toContain('anonymous / (empty)')
    // ...and every label on the band is a credential (contains ` / `); no
    // path (`/`, `/admin`) or SMB-share (`smb`) label survives.
    expect(l1s.every((t) => t.includes(' / '))).toBe(true)
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

  it('joins every kept label to its rise with a stem', () => {
    for (const label of nightLabels()) {
      expect(label.stem, label.l1).toMatch(/^M[\d.]+,[\d.]+ L/)
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
