// Issue #37 acceptance: render the band from each fixture and
// pixel-compare it against the matching reference shot
// (docs/design/concepts/round-6/shots/m-<scene>.png) -- quiet/silent/
// night against the round-6 concept mockups; alerts (issue #45's token
// conflict, throttled, rotation-stalled and not-delivering states)
// against a reference generated from the build, since no concept mockup
// covers it. Starts an in-process vite dev server (fixture mode is
// dev-only, see src/lib/api.ts), screenshots the live <svg
// class="band-svg"> at 1600x1000 @2x -- the same viewport and scale
// docs/design/concepts/round-6/capture.mjs used for the shots -- and
// crops the reference PNG to the same region using the svg's own
// measured bounding box, which is exactly where the band placed its
// content (gen.py's `top`/BAND[-1]+40, ported in src/lib/band/placement.ts
// and model.ts). Exits non-zero if any scene's differing-pixel percentage
// is above 2%.
// Stays on chromium.launch() deliberately (issue #83, owner decision
// 2026-09-19): this is a rendering-fidelity check against the round-6
// references, which were captured in Chromium, not a browser-compatibility
// check, so the browser here is an implementation detail of the reference
// set. See frontend/e2e/browser.mjs, which the behavioural journeys use
// instead.
import { createServer } from 'vite'
import { chromium } from 'playwright'
import { PNG } from 'pngjs'
import pixelmatch from 'pixelmatch'
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const frontendDir = join(here, '..')
const shotsDir = join(frontendDir, '..', 'docs', 'design', 'concepts', 'round-6', 'shots')
const outDir = join(frontendDir, 'scripts', '.out')
mkdirSync(outDir, { recursive: true })

const SCENES = ['quiet', 'silent', 'night', 'alerts']
const THRESHOLD_PCT = 2
const DPR = 2
const PAGE_WIDTH = 1600
const PAGE_HEIGHT = 1000

async function main() {
  // Same in-process server below-band-compare.mjs uses: a spawned vite
  // binary polled over http proved flaky in containers (port reuse and
  // localhost resolving to ::1 while vite listened on 127.0.0.1).
  const server = await createServer({ root: frontendDir, server: { port: 0 } })
  await server.listen()
  const baseUrl = `http://localhost:${server.httpServer.address().port}`

  const results = []
  try {
    const browser = await chromium.launch()
    try {
      const page = await browser.newPage({ viewport: { width: PAGE_WIDTH, height: PAGE_HEIGHT }, deviceScaleFactor: DPR })
      const consoleErrors = []
      page.on('console', (msg) => {
        if (msg.type() === 'error') consoleErrors.push(msg.text())
      })
      page.on('pageerror', (e) => consoleErrors.push(String(e)))

      for (const scene of SCENES) {
        await page.goto(`${baseUrl}/?scene=${scene}`)
        await page.waitForSelector('svg.band-svg', { timeout: 5000 })
        // Let the two effects (ResizeObserver's first callback, the trace
        // fetch) settle before measuring.
        await page.waitForTimeout(150)

        // The svg's own viewBox always reserves BAND[0]-60 of headroom
        // above the top line for the brink line (gen.py's `top`), even
        // with nothing placed there -- in the full concept that headroom
        // sits under the hero sentence (ADR-0004 item 1: the band is
        // "under a sentence that says what matters now"), which isn't
        // part of this slice. Crop to the union of the *content* (every
        // child except the brink line) instead, so an empty scene's crop
        // starts at the top band line rather than borrowing the hero
        // sentence's space from the reference shot.
        // App.svelte's chrome (issue #36) positions the band in normal
        // document flow below a fixed header, not gen.py's absolute
        // 1600x1000 overlay -- so this page's screen (viewport) pixels
        // don't line up with the reference PNG's page-space pixels at any
        // fixed offset. Recover the band's own page-space coordinates from
        // its viewBox (which does use gen.py's numbers, see model.ts) and
        // the screen-space difference between the svg element and its
        // content, then use *that* to index into the reference shot.
        // Content excludes the brink line: its viewBox always reserves
        // BAND[0]-60 of headroom for it even with nothing placed there --
        // in the full concept that headroom sits under the hero sentence
        // (ADR-0004 item 1), which isn't part of this slice.
        const box = await page.evaluate(() => {
          const svg = document.querySelector('svg.band-svg')
          const svgRect = svg.getBoundingClientRect()
          const viewBoxMinY = Number(svg.getAttribute('viewBox').split(' ')[1])
          const children = Array.from(svg.children).filter((el) => !el.classList.contains('brink'))
          const rects = children.map((el) => el.getBoundingClientRect()).filter((r) => r.width > 0 || r.height > 0)
          const screenTop = Math.min(...rects.map((r) => r.y))
          const screenBottom = Math.max(...rects.map((r) => r.y + r.height))
          return {
            screenY: screenTop,
            screenHeight: screenBottom - screenTop,
            pageY: viewBoxMinY + (screenTop - svgRect.y),
          }
        })

        // Full page width -- ADR-0004 item 1, "the full width of the page"
        // -- just the tight content height from above.
        const clip = {
          x: 0,
          y: Math.max(0, box.screenY),
          width: PAGE_WIDTH,
          height: Math.min(box.screenHeight, PAGE_HEIGHT - box.screenY),
        }
        const liveBuf = await page.screenshot({ clip })
        const livePng = PNG.sync.read(liveBuf)

        const shotPath = join(shotsDir, `m-${scene}.png`)
        const shotPng = PNG.sync.read(readFileSync(shotPath))
        // Same page-space region, converted to the shot's pixels (the
        // shots are the 1600x1000 page at @2x, so page-space * DPR).
        const sx = 0
        const sy = Math.round(box.pageY * DPR)
        const sw = PAGE_WIDTH * DPR

        const sh = Math.round(clip.height * DPR)
        const refCrop = new PNG({ width: sw, height: sh })
        PNG.bitblt(shotPng, refCrop, sx, sy, sw, sh, 0, 0)

        if (livePng.width !== refCrop.width || livePng.height !== refCrop.height) {
          results.push({ scene, error: `size mismatch: live ${livePng.width}x${livePng.height} vs ref ${refCrop.width}x${refCrop.height}` })
          continue
        }

        const diffPng = new PNG({ width: livePng.width, height: livePng.height })
        const diffPixels = pixelmatch(livePng.data, refCrop.data, diffPng.data, livePng.width, livePng.height, { threshold: 0.1 })
        const totalPixels = livePng.width * livePng.height
        const pct = (diffPixels / totalPixels) * 100

        writeFileSync(join(outDir, `${scene}-live.png`), PNG.sync.write(livePng))
        writeFileSync(join(outDir, `${scene}-ref.png`), PNG.sync.write(refCrop))
        writeFileSync(join(outDir, `${scene}-diff.png`), PNG.sync.write(diffPng))

        results.push({ scene, pct, diffPixels, totalPixels, consoleErrors: [...consoleErrors] })
        consoleErrors.length = 0
      }
    } finally {
      await browser.close()
    }
  } finally {
    await server.close()
  }

  console.log('')
  let failed = false
  for (const r of results) {
    if (r.error) {
      console.log(`${r.scene}: ERROR -- ${r.error}`)
      failed = true
      continue
    }
    const status = r.pct <= THRESHOLD_PCT ? 'ok' : 'OVER THRESHOLD'
    console.log(`${r.scene}: ${r.pct.toFixed(3)}% differing pixels (${r.diffPixels}/${r.totalPixels}) -- ${status}`)
    if (r.consoleErrors.length) console.log(`  console errors: ${r.consoleErrors.join(' | ')}`)
    if (r.pct > THRESHOLD_PCT) failed = true
  }
  console.log(`\nDiff images written to ${outDir}`)

  process.exit(failed ? 1 : 0)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
