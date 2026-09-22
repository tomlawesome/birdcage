// One place that resolves which Playwright engine a behavioural browser
// journey runs in. Issue #83: the owner browses on Firefox, so Firefox is
// the bar every change has to clear; Safari (WebKit in Playwright) and
// Edge (Chromium with the msedge channel) only widen it at the `preview`
// -> `main` promotion (docs/ci-hops.md, "Hop 2"). AGENTS.md's "Browser
// journeys run in Firefox" line is the standing rule this resolves.
//
// This does not apply to frontend/scripts/band-compare.mjs and
// below-band-compare.mjs: those pixel-compare the rendered page against
// the round-6 design references, which were captured in Chromium. That is
// a rendering-fidelity check against a drawing, not a browser-compatibility
// check, so they keep chromium.launch() on purpose (issue #83, owner
// decision 2026-09-19).
//
// BIRDCAGE_BROWSER selects the engine; unset defaults to firefox. An
// unrecognised value is a hard error rather than a silent fallback to
// Chromium: a run that reports PASS having quietly launched a different
// engine than the one it claims to have tested is worse than one that
// never ran at all.
import { chromium, firefox, webkit } from 'playwright'

const ENGINES = {
  chromium,
  firefox,
  safari: webkit,
  // Edge is not a separate Playwright engine: it is Chromium launched
  // with the msedge channel (`npx playwright install msedge`).
  edge: chromium,
}

const CHANNELS = {
  edge: 'msedge',
}

export function resolveBrowserName() {
  return process.env.BIRDCAGE_BROWSER ?? 'firefox'
}

export async function launchBrowser(name = resolveBrowserName()) {
  const engine = ENGINES[name]
  if (!engine) {
    throw new Error(
      `unknown BIRDCAGE_BROWSER ${JSON.stringify(name)} -- expected one of ${Object.keys(ENGINES).join(', ')}`,
    )
  }
  const options = {}
  if (CHANNELS[name]) options.channel = CHANNELS[name]
  return engine.launch(options)
}
