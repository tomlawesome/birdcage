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
import { launchBrowser, resolveBrowserName } from './browser.mjs'
import { spawn, spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { createServer } from 'node:net'
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

function getFreePort() {
  return new Promise((resolve, reject) => {
    const srv = createServer()
    srv.on('error', reject)
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address()
      srv.close(() => resolve(port))
    })
  })
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
  const caDir = join(workDir, 'ca')

  // Postgres (issue #81) when DATABASE_URL is set -- must already carry
  // sslmode=verify-full (internal/startcheck.PostgresRequiresVerifyFull
  // refuses anything weaker; see docs/ci-hops.md). SQLite otherwise, a
  // fresh file per run exactly as #39 left it.
  const databaseURL = process.env.DATABASE_URL ?? join(workDir, 'seed.db')
  const engine = process.env.DATABASE_URL ? 'postgres' : 'sqlite'

  step(`seeding ${engine === 'postgres' ? '(postgres)' : databaseURL} with the round-6 night story (cmd/seed-story)`)
  const seed = spawnSync('go', ['run', './cmd/seed-story', databaseURL], { cwd: repoRoot, stdio: 'inherit' })
  if (seed.status !== 0) {
    console.error('seed-story failed')
    process.exit(1)
  }
  ok('seeded')

  const httpPort = await getFreePort()
  const enrolPort = await getFreePort()
  const ingestPort = await getFreePort()

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

  console.log(`\nstarting ${BIRDCAGE_BIN} on 127.0.0.1:${httpPort}...`)
  const birdcage = spawn(BIRDCAGE_BIN, [], {
    cwd: repoRoot,
    env: {
      ...sharedEnv,
      BIRDCAGE_HTTP_ADDR: `127.0.0.1:${httpPort}`,
      BIRDCAGE_INGEST_ADDR: `127.0.0.1:${ingestPort}`,
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
    await waitForServer(`http://127.0.0.1:${httpPort}/`)

    console.log(`launching ${resolveBrowserName()}...`)
    browser = await launchBrowser()
    const page = await browser.newPage()

    // Captured for the whole test, but only *enforced* up to the
    // deliberate-failure journey at the end: killing birdcage on purpose
    // to prove the page handles it is not a console-error regression.
    const consoleErrors = []
    page.on('console', (msg) => {
      if (msg.type() === 'error') consoleErrors.push(msg.text())
    })
    page.on('pageerror', (e) => consoleErrors.push(String(e)))

    step('every top-level view renders against the live API with no console error')
    await page.goto(`http://127.0.0.1:${httpPort}/`)
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
    rmSync(workDir, { recursive: true, force: true })
  }

  if (!ok_) {
    console.error('\nbirdcage log:\n' + birdcageLog)
    console.error(`\nsmoke: FAILED -- ${failure?.stack ?? failure}`)
    process.exit(1)
  }
  console.log('\nsmoke: ok')
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
