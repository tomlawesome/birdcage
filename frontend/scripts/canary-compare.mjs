#!/usr/bin/env node
// Issue #118's acceptance check: the canary page renders the four
// round-7 scenes -- quiet and answers when tested; deaf on telnet;
// silent, third time this week; the sweep night from this canary -- the
// way their references do. Same shape as scripts/below-band-compare.mjs:
// a real Vite dev server (fixture mode via ?scene= is dev-only, see
// lib/api.ts), one screenshot per scene at 1600x1000 @2x, pixelmatch
// against the reference, non-zero exit above 2% differing pixels.
//
// Usage: node scripts/canary-compare.mjs            (from frontend/)
//        node scripts/canary-compare.mjs --update   (recapture references)
//
// The references are captured from this build
// (docs/design/concepts/round-7/shots/o-build-*.png), not from the
// concept mockups next to them: the concept's ledger shows an ntp card
// for a lure birdcage does not have, and its facts column names an
// operator birdcage cannot know (issue #8), so the mockups are what the
// page was judged against by eye, and these are what it is held to
// pixel by pixel. Recapture with --update only after looking at the
// result -- see round-7/README.md.
//
// Chromium deliberately, like the other two comparison scripts (#83,
// owner 2026-09-19): this is rendering fidelity against a captured
// reference, not a browser-compatibility check.
import { createServer } from 'vite'
import { chromium } from 'playwright'
import { PNG } from 'pngjs'
import pixelmatch from 'pixelmatch'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const root = join(here, '..')
const shotsDir = join(root, '..', 'docs', 'design', 'concepts', 'round-7', 'shots')
const outDir = join(root, '.canary-compare')
mkdirSync(outDir, { recursive: true })

const SCENES = ['quiet', 'failed', 'silent', 'night']
const VIEWPORT = { width: 1600, height: 1000 }
const SCALE = 2
const THRESHOLD_PCT = 2
const CANARY = 'canary-iot'
const update = process.argv.includes('--update')

const server = await createServer({ root, server: { port: 0 } })
await server.listen()
const baseUrl = `http://localhost:${server.httpServer.address().port}`

const browser = await chromium.launch()
const page = await browser.newPage({ viewport: VIEWPORT, deviceScaleFactor: SCALE })
const consoleErrors = []
page.on('pageerror', (e) => consoleErrors.push(String(e)))

const results = []
try {
  for (const scene of SCENES) {
    await page.goto(`${baseUrl}/?scene=canary-${scene}#/canaries/${CANARY}`, { waitUntil: 'networkidle' })
    // The ledger is the last block to settle (the page's own read lands
    // after the three fleet ones); wait for it, then let the last paint
    // land the way the band comparison does.
    await page.waitForSelector('.strip .svc', { timeout: 5000 })
    await page.waitForTimeout(250)

    const actualBuf = await page.screenshot()
    const referencePath = join(shotsDir, `o-build-${scene}.png`)
    if (update || !existsSync(referencePath)) {
      writeFileSync(referencePath, actualBuf)
      console.log(`${scene}: reference written to ${referencePath}`)
      continue
    }

    const actualPng = PNG.sync.read(actualBuf)
    const referencePng = PNG.sync.read(readFileSync(referencePath))
    if (actualPng.width !== referencePng.width || actualPng.height !== referencePng.height) {
      throw new Error(
        `${scene}: size mismatch -- actual ${actualPng.width}x${actualPng.height}, reference ${referencePng.width}x${referencePng.height}`,
      )
    }

    const { width, height } = actualPng
    const diffPng = new PNG({ width, height })
    const diffPixels = pixelmatch(actualPng.data, referencePng.data, diffPng.data, width, height, { threshold: 0.1 })
    const pct = (diffPixels / (width * height)) * 100

    writeFileSync(join(outDir, `${scene}-actual.png`), PNG.sync.write(actualPng))
    writeFileSync(join(outDir, `${scene}-diff.png`), PNG.sync.write(diffPng))
    results.push({ scene, pct, diffPixels, total: width * height })
    console.log(`${scene}: ${pct.toFixed(3)}% differing pixels (${diffPixels} / ${width * height})`)
  }
} finally {
  await browser.close()
  await server.close()
}

// A page error is a failure even when the pixels agree: a component that
// threw after painting is not a page that works.
if (consoleErrors.length > 0) {
  console.error(`\nPage errors: ${consoleErrors.join(' | ')}`)
  process.exit(1)
}

const failed = results.filter((r) => r.pct > THRESHOLD_PCT)
if (failed.length > 0) {
  console.error(`\nAbove the ${THRESHOLD_PCT}% threshold: ${failed.map((r) => r.scene).join(', ')}`)
  process.exit(1)
}
