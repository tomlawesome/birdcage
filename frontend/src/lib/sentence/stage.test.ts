// ADR-0012 decision 9's stage vocabulary and labels.
import { describe, expect, it } from 'vitest'
import { STAGE_ORDER, stageIndex, stageLabel } from './stage'
import type { RunStage } from '../types'

describe('stage vocabulary', () => {
  it('is the six stages in the ADR order', () => {
    expect(STAGE_ORDER).toEqual(['ordered', 'collected', 'mounts_checked', 'db_refreshed', 'scanning', 'answered'])
  })

  it('every stage has a human label', () => {
    expect(STAGE_ORDER.map(stageLabel)).toEqual([
      'order sent',
      'order received',
      'mounts checked',
      'vulnerability list refreshed',
      'scanning',
      'result received',
    ])
  })

  it('an unknown stage falls back to the raw string', () => {
    expect(stageLabel('made_up' as RunStage)).toBe('made_up')
  })

  it('stageIndex places each stage at its position in the order', () => {
    expect(stageIndex('ordered')).toBe(0)
    expect(stageIndex('answered')).toBe(5)
  })
})
