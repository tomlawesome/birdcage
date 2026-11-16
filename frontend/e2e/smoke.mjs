#!/usr/bin/env node
// Issue #81: the dashboard's live smoke test, widened from #39's original
// four assertions (hero sentence, four tiles) to cover what the dashboard
// now does -- every section rendering against the live API with no
// console error, the range picker actually re-querying, a live SSE
// event, the status strip including the mail item, and a failing API
// read as something other than a blank page. Everything here drives the
// real *birdcage* binary against a seeded database and a real Firefox
// (#83) -- no mocked fetch, no fixture.
//
// Postgres (issue #81's other half): set DATABASE_URL (with
// sslmode=verify-full, matching internal/startcheck.PostgresRequiresVerifyFull
// -- see docs/ci-hops.md and test:go's own Postgres service block) before
// running this script, and it seeds and serves from that database
// instead of a fresh SQLite file. Unset (the default) is SQLite, exactly
// as #39 left it.
//
// The binary itself is not built here (it needs frontend/dist copied into
// web/dist first, which is a whole build step of its own -- see the
// README's "run the frontend" section): point BIRDCAGE_BIN at an
// already-built one, default ../birdcage (repo root, where the CI go job
// builds it).
//
// Usage: node e2e/smoke.mjs   (from frontend/, with BIRDCAGE_BIN set if
// the binary isn't at the default path)
//
// Browser: resolved once, by ./browser.mjs (issue #83) -- BIRDCAGE_BROWSER
// selects it, default firefox.
//
// Sign-in (issue #8, ADR-0016 and ADR-0017): the dashboard API answers
// nothing without a signed-in session. birdcage gets a fresh sign-in key
// file in this run's temporary directory; once it is up, ./signin.mjs
// checks the API refuses everything before the first admin exists, then
// the browser reaches the dashboard through the sign-in screens: first
// run with the setup code from birdcage's log, the authenticator app,
// the recovery codes, enter; then it signs out from the name menu and
// signs in again with the password and an authenticator code. Anything
// printed on a failure goes through signin.mjs's redactSecrets first.
import { launchBrowser, resolveBrowserName } from './browser.mjs'
import { getFreePorts } from './ports.mjs'
import { checkBeforeFirstAdmin, firstAdminThroughScreens, hide, redactCodes, redactSecrets, removeOnExit, setupCodeFrom, signInAgain, writeAuthKeyFile } from './signin.mjs'
import { spawn, spawnSync } from 'node:child_process'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const frontendDir = join(here, '..')
const repoRoot = join(frontendDir, '..')

const BIRDCAGE_BIN = process.env.BIRDCAGE_BIN ?? join(repoRoot, 'birdcage')
const EXPECTED_HERO = 'One address is walking the cage.'
const EXPECTED_TILES = 4

// The live-hit journey's own event (step()). A documentation-only address
// (RFC 5737 TEST-NET-2), chosen so it can never collide with a real
// operator's own traffic and is instantly recognisable in the assertion.
const LIVE_HIT_SOURCE_IP = '198.51.100.77'
const LIVE_HIT_SERVICE = 'ssh'
const LIVE_HIT_DEST_PORT = 22
const LIVE_HIT_RAW = '{"logdata":{"USERNAME":"root","PASSWORD":"toor"}}'

let stepNum = 0
function step(name) {
  stepNum += 1
  console.log(`\nstep ${stepNum}: ${name}`)
}
function ok(msg) {
  console.log(`  ok   ${msg}`)
}

function waitForServer(url, timeoutMs = 15000) {
  const start = Date.now()
  return new Promise((resolve, reject) => {
    const tryOnce = () => {
      fetch(url)
        .then((res) => (res.ok || res.status === 404 ? resolve() : retry()))
        .catch(retry)
    }
    const retry = () => {
      if (Date.now() - start > timeoutMs) reject(new Error(`birdcage did not come up at ${url}`))
      else setTimeout(tryOnce, 200)
    }
    tryOnce()
  })
}

/** Runs a one-shot CLI step (settings/canary-enrol/seed-story) and throws
 * with both streams on a non-zero exit, rather than a bare "status !== 0"
 * the caller has to go dig a log file out for. */
function runCLI(label, cmd, args, env) {
  const res = spawnSync(cmd, args, { cwd: repoRoot, env, encoding: 'utf8' })
  if (res.status !== 0) {
    throw new Error(`${label} failed (exit ${res.status}):\n${res.stdout ?? ''}\n${res.stderr ?? ''}`)
  }
  return res.stdout ?? ''
}

/** Pulls MOCKINGBIRD_CA_PIN and MOCKINGBIRD_DEPLOY_TOKEN out of `birdcage
 * canary enrol`'s printed docker-run command (cmd/birdcage/canary.go's
 * printEnrolRunCommand) -- the same two values an operator would paste
 * into a real canary's environment. */
function parseEnrolOutput(output) {
  const pin = /MOCKINGBIRD_CA_PIN=(\S+)/.exec(output)?.[1]
  const token = /MOCKINGBIRD_DEPLOY_TOKEN=(\S+)/.exec(output)?.[1]
  if (!pin || !token) {
    throw new Error(`could not find MOCKINGBIRD_CA_PIN/MOCKINGBIRD_DEPLOY_TOKEN in enrol output:\n${output}`)
  }
  return { pin, token }
}

async function main() {
  const workDir = mkdtempSync(join(tmpdir(), 'birdcage-smoke-'))
  // The sign-in key lands in workDir, so it goes on every way out: the
  // early process.exit refusals below, a throw caught by main().catch,
  // and Ctrl-C or a CI cancel's SIGTERM -- not only the finally below.
  const removeWorkDir = removeOnExit(workDir)
  const caDir = join(workDir, 'ca')

  // Postgres (issue #81) when DATABASE_URL is set -- must already carry
  // sslmode=verify-full (internal/startcheck.PostgresRequiresVerifyFull
  // refuses anything weaker; see docs/ci-hops.md). SQLite otherwise, a
  // fresh file per run exactly as #39 left it.
  //
  // Everything below seeds fake data into whatever DATABASE_URL points
  // at and overwrites admin_approval_address/release_address
  // unconditionally -- fine against the scratch database CI's own
  // Postgres service provides, not fine against a real fleet's, which
  // a developer's shell could still have exported. Refuse unless
  // whoever set DATABASE_URL also marked it disposable
  // (SMOKE_DATABASE_URL_IS_DISPOSABLE=1) -- test:smoke:postgres does,
  // right next to where it sets DATABASE_URL itself (.gitlab-ci.yml).
  if (process.env.DATABASE_URL && process.env.SMOKE_DATABASE_URL_IS_DISPOSABLE !== '1') {
    console.error(
      'smoke: DATABASE_URL is set but SMOKE_DATABASE_URL_IS_DISPOSABLE=1 is not -- refusing.\n' +
        'This script seeds fake data into DATABASE_URL and overwrites admin_approval_address/release_address\n' +
        'unconditionally. Set SMOKE_DATABASE_URL_IS_DISPOSABLE=1 only if DATABASE_URL is truly a scratch database.'
    )
    process.exit(1)
  }

  const databaseURL = process.env.DATABASE_URL ?? join(workDir, 'seed.db')
  const engine = process.env.DATABASE_URL ? 'postgres' : 'sqlite'

  step(`seeding ${engine === 'postgres' ? '(postgres)' : databaseURL} with the round-6 night story (cmd/seed-story)`)
  const seed = spawnSync('go', ['run', './cmd/seed-story', databaseURL], { cwd: repoRoot, stdio: 'inherit' })
  if (seed.status !== 0) {
    console.error('seed-story failed')
    process.exit(1)
  }
  ok('seeded')

  const [httpPort, enrolPort, ingestPort] = await getFreePorts(3)

  // Shared by every CLI step below and by the server itself -- one CA
  // directory, one advertise host, one enrolment address, so `birdcage
  // canary enrol`'s pin/token are good against the exact enrolment
  // listener the server binds (cmd/birdcage/main.go: BIRDCAGE_INGEST_ADDR
  // gates both the ingest and the enrolment listener).
  const dbEnv = process.env.DATABASE_URL ? { DATABASE_URL: databaseURL } : { BIRDCAGE_DB_PATH: databaseURL }
  const sharedEnv = {
    ...process.env,
    ...dbEnv,
    BIRDCAGE_CA_DIR: caDir,
    BIRDCAGE_ADVERTISE_HOST: '127.0.0.1',
    BIRDCAGE_ENROL_ADDR: `127.0.0.1:${enrolPort}`,
  }

  step('provisioning a live canary for the SSE journey (birdcage settings + canary enrol)')
  // requireEnrolAddresses (cmd/birdcage/canary.go) refuses to mint a
  // deploy token until both settings are non-empty -- values only need to
  // be non-control-character strings (store.validateSettingAddress);
  // nothing here is a real address anything gets sent to.
  runCLI('settings set admin_approval_address', BIRDCAGE_BIN, ['settings', 'set', 'admin_approval_address', 'ops@example.test'], sharedEnv)
  runCLI('settings set release_address', BIRDCAGE_BIN, ['settings', 'set', 'release_address', 'ops@example.test'], sharedEnv)
  const enrolOutput = runCLI('canary enrol', BIRDCAGE_BIN, ['canary', 'enrol', '--name', 'smoke-live', '--lane', 'lan'], sharedEnv)
  const { pin, token } = parseEnrolOutput(enrolOutput)
  ok(`minted a deploy token, pin=${pin.slice(0, 8)}...`)

  // 32 fresh random bytes, mode 0400, removed with workDir on the way out.
  const authKeyFile = writeAuthKeyFile(workDir)

  console.log(`\nstarting ${BIRDCAGE_BIN} on 127.0.0.1:${httpPort}...`)
  const birdcage = spawn(BIRDCAGE_BIN, [], {
    cwd: repoRoot,
    env: {
      ...sharedEnv,
      BIRDCAGE_HTTP_ADDR: `127.0.0.1:${httpPort}`,
      BIRDCAGE_INGEST_ADDR: `127.0.0.1:${ingestPort}`,
      BIRDCAGE_AUTH_KEY_FILE: authKeyFile,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  let birdcageLog = ''
  birdcage.stdout.on('data', (d) => (birdcageLog += d))
  birdcage.stderr.on('data', (d) => (birdcageLog += d))
  birdcage.on('error', (err) => {
    birdcageLog += `\nfailed to start ${BIRDCAGE_BIN}: ${err}\n`
  })

  let ok_ = false
  let failure = null
  let browser = null
  try {
    const base = `http://127.0.0.1:${httpPort}`
    await waitForServer(`${base}/`)

    step('before the first admin: the API answers 503 setup required and refuses a wrong setup code (issue #8)')
    // birdcage writes the code once its sign-in layer has opened, which
    // is before the listener the wait above just reached.
    let setupCode = null
    for (let i = 0; i < 50 && !setupCode; i++) {
      setupCode = setupCodeFrom(birdcageLog)
      if (!setupCode) await new Promise((r) => setTimeout(r, 200))
    }
    if (!setupCode) throw new Error('birdcage never logged a setup code for the first admin')
    hide(setupCode)
    await checkBeforeFirstAdmin(base, ok)

    console.log(`launching ${resolveBrowserName()}...`)
    browser = await launchBrowser()
    // 1400x1000 (issue #58's own reproduction viewport): the round-6
    // story's sweep always lands in the last quarter hour, stretched
    // against the axis, so four canaries' credential rises land close
    // together near the right edge on every run -- exactly the crowding
    // the label-collapse assertion below needs to be a real check rather
    // than a check that happens to have nothing to catch.
    const context = await browser.newContext({ viewport: { width: 1400, height: 1000 } })
    const page = await context.newPage()

    // Captured for the whole test, but only *enforced* up to the
    // deliberate-failure journey at the end: killing birdcage on purpose
    // to prove the page handles it is not a console-error regression.
    const consoleErrors = []
    page.on('console', (msg) => {
      if (msg.type() === 'error') consoleErrors.push(msg.text())
    })
    page.on('pageerror', (e) => consoleErrors.push(String(e)))

    step('signing in through the screens: first run, authenticator app, recovery codes, enter (issue #8)')
    await page.goto(`${base}/`)
    const account = await firstAdminThroughScreens(page, setupCode, ok)
    const { username } = account
    const who = (await page.locator('.status .who').textContent({ timeout: 10000 }))?.trim()
    if (who !== `${username} (admin)`) throw new Error(`name chip: expected ${JSON.stringify(`${username} (admin)`)}, got ${JSON.stringify(who)}`)
    ok(`name chip: ${who}`)

    step('signing out from the name menu, then in again with the password and an authenticator code (issue #8)')
    await signInAgain(page, account, ok)
    const whoAgain = (await page.locator('.status .who').textContent({ timeout: 10000 }))?.trim()
    if (whoAgain !== `${username} (admin)`) throw new Error(`name chip after signing in again: got ${JSON.stringify(whoAgain)}`)
    ok(`name chip: ${whoAgain}`)

    step('every top-level view renders against the live API with no console error')
    await page.waitForSelector('.hero', { timeout: 10000 })
    const hero = (await page.textContent('.hero'))?.trim()
    const tileCount = await page.locator('.tile').count()
    if (hero !== EXPECTED_HERO) {
      throw new Error(`hero sentence: expected ${JSON.stringify(EXPECTED_HERO)}, got ${JSON.stringify(hero)}`)
    }
    if (tileCount !== EXPECTED_TILES) {
      throw new Error(`expected ${EXPECTED_TILES} .tile elements, found ${tileCount}`)
    }
    ok(`hero: ${hero}`)
    ok(`tiles: ${tileCount}`)
    const bandCount = await page.locator('.band-svg').count()
    if (bandCount !== 1) throw new Error(`expected the trace band to render once, found ${bandCount}`)
    ok('band (the trace) rendered')

    // Issue #58: coincident trace labels used to stack straight past the
    // top of the chart and into the header above it. The chart's own box
    // has no dedicated element to measure, so this reads it off the page
    // itself -- nothing the trace draws may reach above where the sub
    // sentence ends, and specifically never over the hero sentence or the
    // name chip, which is what the fix (frontend/src/lib/band/placement.ts)
    // is meant to guarantee under any data.
    const chartFloor = await page.evaluate(() => document.querySelector('.sub').getBoundingClientRect().bottom)
    const [heroBox, whoBox, labelBoxes] = await Promise.all([
      page.locator('.hero').first().boundingBox(),
      page.locator('.status .who').first().boundingBox(),
      page.evaluate(() =>
        [...document.querySelectorAll('svg.band-svg text.bl:not(.dim)')].map((t) => {
          const r = t.getBoundingClientRect()
          return { text: t.textContent, top: r.top, bottom: r.bottom, left: r.left, right: r.right }
        }),
      ),
    ])
    const rectOverlaps = (a, b) => a.left < b.right && a.right > b.left && a.top < b.bottom && a.bottom > b.top
    if (labelBoxes.length === 0) throw new Error('expected at least one trace label to check against the chart box')
    for (const box of labelBoxes) {
      if (box.top < chartFloor) {
        throw new Error(`trace label ${JSON.stringify(box.text)} reaches above the chart box (top=${box.top}, chart floor=${chartFloor})`)
      }
      if (rectOverlaps(box, heroBox)) {
        throw new Error(`trace label ${JSON.stringify(box.text)} overlaps the hero sentence`)
      }
      if (rectOverlaps(box, whoBox)) {
        throw new Error(`trace label ${JSON.stringify(box.text)} overlaps the name chip`)
      }
    }
    for (let i = 0; i < labelBoxes.length; i++) {
      for (let j = i + 1; j < labelBoxes.length; j++) {
        if (rectOverlaps(labelBoxes[i], labelBoxes[j])) {
          throw new Error(`trace labels overlap each other: ${JSON.stringify(labelBoxes[i].text)} / ${JSON.stringify(labelBoxes[j].text)}`)
        }
      }
    }
    ok(`${labelBoxes.length} trace labels, all within the chart box, clear of the hero sentence and the name chip`)
    const historyCount = await page.locator('.history').count()
    if (historyCount !== 1) throw new Error('the state history section did not render')
    ok('state history rendered')
    const eventRows = await page.locator('.row').count()
    if (eventRows === 0) throw new Error('the events section rendered no rows for a story with visitors')
    ok(`events: ${eventRows} rows`)

    // The tabs and the sideways deck (App.svelte's TABS/DECK) are chrome
    // only today -- clicking them moves the active button but nothing in
    // <main> is conditioned on either state, so there is exactly one
    // top-level view to check against a console error, not several. This
    // still exercises every click the operator can make.
    for (const tab of await page.locator('.tabs button').all()) {
      await tab.click()
    }
    for (const item of await page.locator('.deck button').all()) {
      await item.click()
    }
    if (consoleErrors.length > 0) {
      throw new Error(`browser console errors: ${consoleErrors.join(' | ')}`)
    }
    ok('every tab/deck control clicked with no console error')

    step('the range picker re-queries and re-renders, not just repaints')
    const before = await page.locator('.tiles').innerText()
    const [rangeResponse] = await Promise.all([
      page.waitForResponse((r) => r.url().includes('/api/canaries?range=90d'), { timeout: 10000 }),
      page.locator('.ranges button', { hasText: '90 d' }).click(),
    ])
    if (!rangeResponse.ok()) throw new Error(`range re-query answered ${rangeResponse.status()}`)
    await page.waitForFunction(
      (prev) => document.querySelector('.tiles')?.innerText !== prev,
      before,
      { timeout: 10000 },
    )
    const after = await page.locator('.tiles').innerText()
    ok(`90d re-query landed and the tiles' rendered text changed (${before.length} -> ${after.length} chars, content differs)`)
    if (consoleErrors.length > 0) {
      throw new Error(`browser console errors after the range change: ${consoleErrors.join(' | ')}`)
    }

    step('the status strip reports the seeded story, including the mail item')
    const statusText = (await page.locator('.status').innerText()).replace(/\s+/g, ' ')
    if (!/visitors/.test(statusText)) throw new Error(`status strip did not mention visitors: ${statusText}`)
    if (!/LIVE/.test(statusText)) throw new Error(`status strip did not read LIVE for the sweep-night story: ${statusText}`)
    // No mail configuration is set anywhere in this script, so the
    // seeded story implies "mail off" (frontend/src/lib/sentence/mail.ts:
    // Configured defaults to false, and GET /api/mail always answers 200
    // -- see internal/api/handlers.go's handleMail doc comment) -- this
    // is genuinely what the story implies, not a fixture standing in for it.
    if (!/mail off/.test(statusText)) throw new Error(`status strip did not report "mail off": ${statusText}`)
    ok(`status strip: ${statusText}`)

    step('a live event over the real ingest path reaches an already-open dashboard via SSE')
    // internal/stream.Hub.PublishAlert is called from exactly one place,
    // internal/ingest/batch.go's handleBatch -- a row written straight
    // into the database (the way this script seeds everything else)
    // never reaches it, so this runs the real enrol-then-push handshake
    // (cmd/e2e-live-hit, built on the same internal/agent/enrol and
    // internal/agent/client packages the real mockingbird agent uses)
    // against the enrolment/ingest listeners the server just started.
    const liveHit = spawnSync(
      'go',
      [
        'run',
        './cmd/e2e-live-hit',
        '-enrol-url', `https://127.0.0.1:${enrolPort}`,
        '-pin', pin,
        '-token', token,
        '-source-ip', LIVE_HIT_SOURCE_IP,
        '-dest-port', String(LIVE_HIT_DEST_PORT),
        '-service', LIVE_HIT_SERVICE,
        '-raw', LIVE_HIT_RAW,
      ],
      { cwd: repoRoot, encoding: 'utf8' },
    )
    if (liveHit.status !== 0) {
      throw new Error(`e2e-live-hit failed:\n${liveHit.stdout}\n${liveHit.stderr}`)
    }
    ok(liveHit.stdout.trim())
    // The dashboard's own poll is REFRESH_MS=30s (frontend/src/App.svelte);
    // waiting well under that for the injected visitor's address to
    // appear is what makes this a proof of the SSE push and not a proof
    // that the poll eventually would have found it too.
    const sseDeadlineMs = 10000
    await page.waitForFunction(
      (ip) => Array.from(document.querySelectorAll('.row .ip')).some((el) => el.textContent === ip),
      LIVE_HIT_SOURCE_IP,
      { timeout: sseDeadlineMs },
    )
    ok(`event from ${LIVE_HIT_SOURCE_IP} reached the page within ${sseDeadlineMs}ms of the push -- the SSE path, not the 30s poll`)
    if (consoleErrors.length > 0) {
      throw new Error(`browser console errors after the live event: ${consoleErrors.join(' | ')}`)
    }

    step('a failing API is handled: the page says something useful, not blank')
    const heroBeforeOutage = await page.textContent('.hero')
    birdcage.kill()
    // A range change forces an immediate refetch (App.svelte's $effect
    // reruns on activeRange) rather than waiting up to REFRESH_MS for the
    // next poll tick, so this assertion doesn't need a 30s-scale timeout.
    await page.locator('.ranges button', { hasText: '15 m' }).click()
    await page.waitForSelector('.foot :text("the cage is not answering")', { timeout: 10000 })
    const heroDuringOutage = await page.textContent('.hero')
    if (heroDuringOutage !== heroBeforeOutage) {
      throw new Error('the page went blank (or changed) instead of keeping the last-known view during the outage')
    }
    ok('footer reported "the cage is not answering" and the rest of the page kept showing the last-known state')

    ok_ = true
  } catch (err) {
    failure = err
  } finally {
    if (browser) await browser.close()
    birdcage.kill()
    removeWorkDir()
  }

  if (!ok_) {
    // The one-time setup and unlock codes are blanked: either one hands
    // whoever reads the log an admin account.
    console.error(redactSecrets('\nbirdcage log:\n' + redactCodes(birdcageLog)))
    console.error(redactSecrets(`\nsmoke: FAILED -- ${failure?.stack ?? failure}`))
    process.exit(1)
  }
  console.log('\nsmoke: ok')
}

main().catch((err) => {
  console.error(redactSecrets(err?.stack ?? err))
  process.exit(1)
})
