// The self-test ledger (ADR-0004 rule 3): one card per service,
// outlined in the grade's colour, with the grade word under the answer.
// Only the words live here -- CanaryPage.svelte draws the strip, and
// lib/canary/model.ts decides which cards there are.
import type { Segment } from '../sentence/types'
import type { SelfTestCard } from './model'

/** The answer line, with the mark the concept puts in front of it: a
 * filled dot for a service that answered, a hollow one for a service
 * that did not. Untested carries no mark at all -- it is not a verdict. */
export function answerWords(card: SelfTestCard): string {
  switch (card.outcome) {
    case 'passed':
      return '● answered'
    case 'failed':
      return '○ did not answer'
    default:
      return 'untested'
  }
}

/** The grade word under the answer. A pass says how strong the proof
 * was; a failure says there was none; an untested service says why
 * there is nothing to grade -- and none of the three is a fault, which
 * is the whole point of the ADR's third card. */
export function gradeWords(card: SelfTestCard): string {
  if (card.outcome === 'failed') return 'no proof'
  if (card.outcome === 'untested') return 'not probed in this run'
  switch (card.grade) {
    case 'challenge_marked':
      return 'challenge-marked'
    case 'attributed':
      return 'attributed'
    default:
      return 'marked'
  }
}

/** The card's outline class: the grade's colour for a pass, ink for a
 * service that did not answer, dashed ink-3 for untested. */
export function cardClass(card: SelfTestCard): string {
  if (card.outcome === 'failed') return 'no'
  if (card.outcome === 'untested') return 'un'
  return ''
}

/** The note under the strip: what the three grades mean, and that
 * untested is not a fault. Fixed copy -- it explains birdcage's own
 * proof model, which does not vary by canary. */
export const SELF_TEST_NOTE: Segment[] = [
  { text: 'Three grades of proof, all a pass: ' },
  { text: 'marked', bold: true },
  { text: " — the probe's marker came back in the event; " },
  { text: 'challenge-marked', bold: true },
  { text: ' — the marker was a signed answer to a challenge (vnc); ' },
  { text: 'attributed', bold: true },
  {
    text:
      ' — no marker can travel, so the agent claims its own probe as it leaves and birdcage matches the claim. ' +
      'Untested is not a fault: the run carried no target for that service.',
  },
]
