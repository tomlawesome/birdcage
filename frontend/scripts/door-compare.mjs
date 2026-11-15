// Issue #8 slice B's pixel gate (docs/design/sign-in-screens.md, "Pixel
// gate", stage porting): the built sign-in door against the ratified
// round-18 mock-up (docs/design/concepts/round-18/direction-an-bars-all-
// screens.html), screen by screen, each at the frozen moment the
// mock-up's shot.mjs uses: sign in, first run, choose, prove, codes and
// session expired. Both sides are rendered here, in the same browser at
// 1440x900 @2x (shot.mjs's viewport), so no reference files are kept:
// the mock-up itself is the reference, opened from disk with its `?t=`
// and `#<state>`; the build is scripts/door-harness.html on an
// in-process vite dev server, with the bars frozen at the same moment
// (frozenAt) and the auth API answered here.
//
// The mock-up is changed only where the specification says the build
// cannot be true, and nowhere else:
// - its bottom-left prototype links (`.proto`) are hidden;
// - its QR placeholder draws a made-up pattern, not a code: the QR
//   region (the mock-up's #qr and the build's .qr, the union of the two
//   boxes) is masked to one flat colour on both sides before comparing;
// - of the five text differences the spec lists ("Where the mock-up
//   cannot be true"), only the session-expired subtitle falls on a
//   compared screen, and the mock-up's text is replaced by the built
//   text. The refused and too-many-attempts texts are on screens not
//   compared here; the account name under "Session expired" is shown,
//   since this harness's tab knows it ('ada', as the mock-up).
// Exits non-zero if any screen differs by more than 0.1%, if the build's
// bars are not drawn (the bars are about 2% of the frame, so a blank
// canvas alone could pass a looser limit), or if either page logs an
// error.
//
// Stays on chromium.launch(), as band-compare.mjs does (issue #83): a
// rendering-fidelity check, not a browser-compatibility one.
import { createServer } from 'vite'
import { chromium } from 'playwright'
import { PNG } from 'pngjs'
import pixelmatch from 'pixelmatch'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const frontendDir = join(here, '..')
const mockDir = join(frontendDir, '..', 'docs', 'design', 'concepts', 'round-18')
const mockUrl = pathToFileURL(join(mockDir, 'direction-an-bars-all-screens.html')).href
const outDir = join(frontendDir, '.door-compare')
mkdirSync(outDir, { recursive: true })

const THRESHOLD_PCT = 0.1
// The bars must cover at least this share of the frame in the build's
// shot: measured as the pixels that change when the bars canvas is
// hidden. They cover about 2%; a blank or missing canvas covers none.
const MIN_BARS_PCT = 0.5
const VIEWPORT = { width: 1440, height: 900 }
const DPR = 2
// shot.mjs waits 900ms for the entrance animations; a little more here,
// since the build also waits on its session read.
const SETTLE_MS = 1200

// The mock-up's own example secret and codes, read from its page, so
// both sides show the same text.
const mockHtml = readFileSync(join(mockDir, 'direction-an-bars-all-screens.html'), 'utf8')
const SECRET = (/class="secret">([^<]+)</.exec(mockHtml)?.[1] ?? '').replace(/\s+/g, '')
const CODES = [...(/class="grid">(.*?)<\/div>/.exec(mockHtml)?.[1] ?? '').matchAll(/<span>([^<]+)<\/span>/g)].map((m) => m[1])
if (!SECRET || CODES.length !== 10) throw new Error('door-compare: could not read the secret and ten codes from the mock-up')
const EXPIRED_SUBTITLE = 'Enter your password to continue.'

const signedOut = {
  setupRequired: false,
  ssoAvailable: true,
  authenticated: false,
  hasLocalPassword: false,
  ssoConnected: false,
  mustChangePassword: false,
  mustEnrolSecondFactor: false,
  mustEnrolPasskey: false,
  hasTOTP: false,
}
const firstRun = { ...signedOut, setupRequired: true, ssoAvailable: false }
const owesStep = {
  ...signedOut,
  ssoAvailable: false,
  authenticated: true,
  hasLocalPassword: true,
  mustEnrolSecondFactor: true,
  username: 'ada',
  role: 'admin',
  passkeys: { count: 0, status: 'ready', origin: 'https://birdcage.example', signIn: false },
}
const expired = { ...signedOut, resumable: true, username: 'ada', passkeys: { count: 1, status: 'ready', signIn: true } }

async function fillFirstRun(page) {
  await page.fill('input[placeholder="setup code"]', 'ABCD-EFGH')
  await page.fill('input[placeholder="account"]', 'ada')
  await page.fill('input[placeholder="password"]', 'correct horse battery')
  await page.fill('input[placeholder="confirm password"]', 'correct horse battery')
  await page.click('button.submit')
  await page.click('button.key:has-text("Authenticator app")')
  await page.waitForSelector('.secret')
}

// name, the mock-up's state and ?t= (shot.mjs), the session the build
// starts from, and how the build reaches the screen from there.
const SCREENS = [
  {
    name: 'signin',
    state: 'signin',
    t: 12,
    session: signedOut,
    // The mock-up fills the account with 'ada' and focuses the password.
    drive: async (page) => {
      await page.fill('input[placeholder="account"]', 'ada')
      await page.focus('input[placeholder="password"]')
    },
  },
  { name: 'first-run', state: 'firstrun', t: 10, session: firstRun },
  { name: 'choose', state: 'choose', t: 14, session: owesStep },
  { name: 'prove', state: 'prove', t: 20, session: firstRun, drive: fillFirstRun },
  {
    name: 'codes',
    state: 'codes',
    t: 30,
    session: firstRun,
    drive: async (page) => {
      await fillFirstRun(page)
      await page.fill('input[placeholder="6-digit code"]', '123456')
      await page.click('button.submit')
      await page.waitForSelector('.grid span')
      // the mock-up arrives at this screen with nothing focused
      await page.evaluate(() => document.activeElement instanceof HTMLElement && document.activeElement.blur())
    },
  },
  { name: 'expired', state: 'expired', t: 24, session: expired, shell: true },
]

/** Answer the auth API the way gauntlet would for these journeys. */
async function answerAuth(page, start) {
  let session = start
  const json = (route, body, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })
  await page.route('**/api/auth/**', (route) => {
    const path = new URL(route.request().url()).pathname
    if (path === '/api/auth/session') return json(route, session)
    if (path === '/api/auth/register') {
      session = owesStep
      return json(route, { username: 'ada', role: 'admin' })
    }
    if (path === '/api/auth/totp/enrol') return json(route, { uri: `otpauth://totp/birdcage:ada?secret=${SECRET}`, secret: SECRET })
    if (path === '/api/auth/totp/confirm') return json(route, { recoveryCodes: CODES })
    return json(route, { type: 'about:blank', title: 'not in this harness' }, 404)
  })
  await page.route('**/__door-shell.jpg', (route) => route.fulfill({ status: 200, contentType: 'image/jpeg', body: readFileSync(join(mockDir, 'dashboard.jpg')) }))
}

async function shoot(page) {
  await page.mouse.move(0, 0)
  await page.waitForTimeout(SETTLE_MS)
  return PNG.sync.read(await page.screenshot({ caret: 'hide' }))
}

/** The QR box on the page, in device pixels, or null when not shown. */
async function qrBox(page, selector) {
  const box = await page.evaluate((sel) => {
    const el = document.querySelector(sel)
    if (!el) return null
    const r = el.getBoundingClientRect()
    return r.width && r.height ? { x0: r.left, y0: r.top, x1: r.right, y1: r.bottom } : null
  }, selector)
  if (!box) return null
  return { x0: Math.floor(box.x0 * DPR), y0: Math.floor(box.y0 * DPR), x1: Math.ceil(box.x1 * DPR), y1: Math.ceil(box.y1 * DPR) }
}

/** Paints the box one flat colour in each image. */
function mask(box, ...images) {
  for (const img of images) {
    for (let y = Math.max(0, box.y0); y < Math.min(img.height, box.y1); y++) {
      for (let x = Math.max(0, box.x0); x < Math.min(img.width, box.x1); x++) {
        const i = (y * img.width + x) * 4
        img.data[i] = 255
        img.data[i + 1] = 0
        img.data[i + 2] = 255
        img.data[i + 3] = 255
      }
    }
  }
}

/** The share of the frame, in percent, the bars canvas draws: the
 * pixels that differ between the shot and a shot with it hidden. */
async function barsShare(page, shot) {
  await page.addStyleTag({ content: '.door .bars{visibility:hidden !important}' })
  const bare = PNG.sync.read(await page.screenshot({ caret: 'hide' }))
  if (bare.width !== shot.width || bare.height !== shot.height) return 0
  const changed = pixelmatch(shot.data, bare.data, null, shot.width, shot.height, { threshold: 0.1 })
  return (changed / (shot.width * shot.height)) * 100
}

async function main() {
  const server = await createServer({ root: frontendDir, server: { port: 0 }, logLevel: 'warn' })
  await server.listen()
  const baseUrl = `http://localhost:${server.httpServer.address().port}`

  const results = []
  try {
    const browser = await chromium.launch()
    try {
      for (const s of SCREENS) {
        const errors = []
        const newPage = async () => {
          const page = await browser.newPage({ viewport: VIEWPORT, deviceScaleFactor: DPR })
          page.on('console', (msg) => msg.type() === 'error' && errors.push(msg.text()))
          page.on('pageerror', (e) => errors.push(String(e)))
          return page
        }

        const mock = await newPage()
        await mock.goto(`${mockUrl}?t=${s.t}#${s.state}`)
        await mock.addStyleTag({ content: '.proto{display:none}' })
        await mock.evaluate((text) => {
          const sub = document.querySelector('#f-expired .subtitle')
          if (sub) sub.textContent = text
        }, EXPIRED_SUBTITLE)
        const ref = await shoot(mock)
        const refQr = await qrBox(mock, '#qr')
        await mock.close()

        const built = await newPage()
        await answerAuth(built, s.session)
        const shell = s.shell ? `&shell=${encodeURIComponent('/__door-shell.jpg')}` : ''
        await built.goto(`${baseUrl}/scripts/door-harness.html?t=${s.t}${shell}`)
        await built.waitForSelector('body[data-ready="1"] .door form', { timeout: 10000 })
        if (s.drive) await s.drive(built)
        const live = await shoot(built)
        const liveQr = await qrBox(built, '.door .qr')
        const bars = await barsShare(built, live)
        await built.close()

        if (live.width !== ref.width || live.height !== ref.height) {
          results.push({ name: s.name, error: `size mismatch: built ${live.width}x${live.height}, mock-up ${ref.width}x${ref.height}` })
          continue
        }
        if (refQr || liveQr) {
          const boxes = [refQr, liveQr].filter(Boolean)
          const union = {
            x0: Math.min(...boxes.map((b) => b.x0)),
            y0: Math.min(...boxes.map((b) => b.y0)),
            x1: Math.max(...boxes.map((b) => b.x1)),
            y1: Math.max(...boxes.map((b) => b.y1)),
          }
          mask(union, live, ref)
        }
        const diff = new PNG({ width: live.width, height: live.height })
        const diffPixels = pixelmatch(live.data, ref.data, diff.data, live.width, live.height, { threshold: 0.1 })
        const totalPixels = live.width * live.height
        writeFileSync(join(outDir, `${s.name}-live.png`), PNG.sync.write(live))
        writeFileSync(join(outDir, `${s.name}-ref.png`), PNG.sync.write(ref))
        writeFileSync(join(outDir, `${s.name}-diff.png`), PNG.sync.write(diff))
        results.push({ name: s.name, pct: (diffPixels / totalPixels) * 100, diffPixels, totalPixels, bars, errors })
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
      console.log(`${r.name}: ERROR -- ${r.error}`)
      failed = true
      continue
    }
    const over = r.pct > THRESHOLD_PCT
    const noBars = r.bars < MIN_BARS_PCT
    console.log(
      `${r.name}: ${r.pct.toFixed(3)}% differing pixels (${r.diffPixels}/${r.totalPixels}), bars ${r.bars.toFixed(2)}% of the frame -- ${over ? 'OVER THRESHOLD' : noBars ? 'BARS NOT DRAWN' : 'ok'}`,
    )
    if (r.errors.length) console.log(`  console errors: ${r.errors.join(' | ')}`)
    // A page error fails the screen even when the pixels agree, as in
    // band-compare.mjs and canary-compare.mjs.
    if (over || noBars || r.errors.length) failed = true
  }
  console.log(`\nDiff images written to ${outDir}`)
  process.exit(failed ? 1 : 0)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
