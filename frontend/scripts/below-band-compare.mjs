#!/usr/bin/env node
// Issue #38's acceptance check: from each fixture, the page below the
// band matches docs/design/concepts/round-6/shots/m-*.png by
// pixelmatch -- quiet/silent/night against the round-6 concept mockups;
// alerts (issue #45's token conflict, throttled, rotation-stalled and
// not-delivering states) against a reference generated from the build,
// since no concept mockup covers it. Starts a real Vite dev server
// (fixture mode via ?scene= only works in dev -- see lib/api.ts's
// fixtureScene()), screenshots each scene at 1600x1000 @2x (matching
// round-6/capture.mjs exactly), crops out the band, and diffs against
// the reference shot cropped the same way.
//
// Usage: node scripts/below-band-compare.mjs   (from frontend/)
import { createServer } from 'vite'
import { chromium } from 'playwright'
import { PNG } from 'pngjs'
import pixelmatch from 'pixelmatch'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const root = join(here, '..')
const shotsDir = join(root, '..', 'docs', 'design', 'concepts', 'round-6', 'shots')
const outDir = join(root, '.below-band-compare')
mkdirSync(outDir, { recursive: true })

const SCENES = ['quiet', 'silent', 'night', 'alerts']
const VIEWPORT = { width: 1600, height: 1000 }
const SCALE = 2
const THRESHOLD_PCT = 2

// gen.py puts the tiles' top edge at css y=430 (TILE_TOP) and the band's
// lowest content (the axis labels) ends around y=384 -- comfortably
// above it. 420 sits in that gap: everything the band slice owns is
// excluded (this worktree doesn't render it), everything this issue
// owns (tiles, events, legend, footer) is included. At the 2x device
// scale factor that is physical row 840, in both our screenshot and the
// reference shot (already 3200x2000 -- 2x of the concept's 1600x1000).
const CROP_TOP_CSS = 420
const CROP_TOP = CROP_TOP_CSS * SCALE

function cropPng(png, top) {
  const height = png.height - top
  const out = new PNG({ width: png.width, height })
  PNG.bitblt(png, out, 0, top, png.width, height, 0, 0)
  return out
}

const server = await createServer({ root, server: { port: 0 } })
await server.listen()
const address = server.httpServer.address()
const baseUrl = `http://localhost:${address.port}`

const browser = await chromium.launch()
const page = await browser.newPage({ viewport: VIEWPORT, deviceScaleFactor: SCALE })

const results = []
try {
  for (const scene of SCENES) {
    await page.goto(`${baseUrl}/?scene=${scene}`, { waitUntil: 'networkidle' })
    await page.waitForSelector('.tiles .tile', { timeout: 5000 })
    // Events/status settle a tick after the tiles do (a second effect,
    // a second fixture import); give the last paint a moment to land.
    await page.waitForTimeout(200)

    const actualPng = cropPng(PNG.sync.read(await page.screenshot()), CROP_TOP)
    const referencePng = cropPng(PNG.sync.read(readFileSync(join(shotsDir, `m-${scene}.png`))), CROP_TOP)

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
    console.log(`${scene}: ${pct.toFixed(2)}% differing pixels (${diffPixels} / ${width * height})`)
  }
} finally {
  await browser.close()
  await server.close()
}

const failed = results.filter((r) => r.pct > THRESHOLD_PCT)
if (failed.length > 0) {
  console.error(`\nAbove the ${THRESHOLD_PCT}% threshold: ${failed.map((r) => r.scene).join(', ')}`)
  process.exit(1)
}
