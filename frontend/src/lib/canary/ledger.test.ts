import { describe, expect, it } from 'vitest'
import { plainText } from '../sentence/types'
import { answerWords, cardClass, gradeWords, SELF_TEST_NOTE } from './ledger'
import type { SelfTestCard } from './model'

function card(overrides: Partial<SelfTestCard> = {}): SelfTestCard {
  return { service: 'ssh', port: '22', outcome: 'passed', grade: 'marked', lure: false, ...overrides }
}

describe('a card says what happened, then how strong the proof was', () => {
  it('answered, with its grade', () => {
    expect(answerWords(card())).toBe('● answered')
    expect(gradeWords(card())).toBe('marked')
    expect(gradeWords(card({ grade: 'challenge_marked' }))).toBe('challenge-marked')
    expect(gradeWords(card({ grade: 'attributed' }))).toBe('attributed')
    expect(cardClass(card())).toBe('')
  })

  it('did not answer: a hollow mark, and no proof at all', () => {
    const failed = card({ outcome: 'failed', grade: null })
    expect(answerWords(failed)).toBe('○ did not answer')
    expect(gradeWords(failed)).toBe('no proof')
    expect(cardClass(failed)).toBe('no')
  })

  it('untested is not a fault -- no verdict mark, and the dashed outline', () => {
    const untested = card({ outcome: 'untested', grade: null })
    expect(answerWords(untested)).toBe('untested')
    expect(gradeWords(untested)).toBe('not probed in this run')
    expect(cardClass(untested)).toBe('un')
  })
})

describe('the note under the strip', () => {
  it('names all three grades as a pass, and says untested is not a fault', () => {
    const note = plainText(SELF_TEST_NOTE)
    expect(note).toContain('Three grades of proof, all a pass')
    for (const grade of ['marked', 'challenge-marked', 'attributed']) expect(note).toContain(grade)
    expect(note).toContain('Untested is not a fault')
  })
})
