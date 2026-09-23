// The four round-7 canary scenes, as the unit tests read them: the same
// JSON the dev scenes and the pixel gate use, so a copy assertion here
// and the rendered page can never drift apart. Test-only -- nothing in
// the app imports this, and a production build never reaches it.
import canaryFailed from '../../dev/fixtures/canary-failed.json'
import canaryNight from '../../dev/fixtures/canary-night.json'
import canaryQuiet from '../../dev/fixtures/canary-quiet.json'
import canarySilent from '../../dev/fixtures/canary-silent.json'
import type { CanaryPageInput } from './model'

const SCENES = {
  quiet: canaryQuiet,
  failed: canaryFailed,
  silent: canarySilent,
  night: canaryNight,
} as unknown as Record<string, {
  trace: CanaryPageInput['trace']
  visitors: { visitors: CanaryPageInput['visitors'] }
  history: CanaryPageInput['history']
  canary: Record<string, CanaryPageInput['page']>
}>

export type SceneName = 'quiet' | 'failed' | 'silent' | 'night'

/** One scene's page input, for the canary the scene is about. */
export function sceneInput(scene: SceneName, canaryId = 'canary-iot'): CanaryPageInput {
  const fixture = SCENES[scene]
  return {
    page: structuredClone(fixture.canary[canaryId]),
    trace: structuredClone(fixture.trace),
    visitors: structuredClone(fixture.visitors.visitors),
    history: structuredClone(fixture.history),
  }
}
