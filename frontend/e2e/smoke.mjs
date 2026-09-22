#!/usr/bin/env node
// Issue #39's acceptance check: seed a fresh SQLite database with the
// round-6 sweep-night story (cmd/seed-story), start the *built* birdcage
// binary against it on a free port, load / in a real browser, and assert
// the sweep sentence and four canary tiles render -- the dashboard
// actually talking to the live API, not a fixture. Runs on SQLite only;
// Postgres at the preview bar is #7's concern.
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

async function main() {
  const workDir = mkdtempSync(join(tmpdir(), 'birdcage-smoke-'))
  const dbPath = join(workDir, 'seed.db')

  console.log(`seeding ${dbPath} with the round-6 night story (cmd/seed-story)...`)
  const seed = spawnSync('go', ['run', './cmd/seed-story', dbPath], { cwd: repoRoot, stdio: 'inherit' })
  if (seed.status !== 0) {
    console.error('seed-story failed')
    process.exit(1)
  }

  const httpPort = await getFreePort()
  const syslogPort = await getFreePort()

  console.log(`starting ${BIRDCAGE_BIN} on 127.0.0.1:${httpPort}...`)
  const birdcage = spawn(BIRDCAGE_BIN, [], {
    cwd: repoRoot,
    env: {
      ...process.env,
      BIRDCAGE_DB_PATH: dbPath,
      BIRDCAGE_HTTP_ADDR: `127.0.0.1:${httpPort}`,
      BIRDCAGE_SYSLOG_ADDR: `127.0.0.1:${syslogPort}`,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  let birdcageLog = ''
  birdcage.stdout.on('data', (d) => (birdcageLog += d))
  birdcage.stderr.on('data', (d) => (birdcageLog += d))
  birdcage.on('error', (err) => {
    birdcageLog += `\nfailed to start ${BIRDCAGE_BIN}: ${err}\n`
  })

  let ok = false
  let failure = null
  try {
    await waitForServer(`http://127.0.0.1:${httpPort}/`)

    console.log(`launching ${resolveBrowserName()}...`)
    const browser = await launchBrowser()
    try {
      const page = await browser.newPage()
      const consoleErrors = []
      page.on('console', (msg) => {
        if (msg.type() === 'error') consoleErrors.push(msg.text())
      })
      page.on('pageerror', (e) => consoleErrors.push(String(e)))

      await page.goto(`http://127.0.0.1:${httpPort}/`)
      await page.waitForSelector('.hero', { timeout: 10000 })
      const hero = (await page.textContent('.hero'))?.trim()
      const tileCount = await page.locator('.tile').count()

      console.log(`hero: ${hero}`)
      console.log(`tiles: ${tileCount}`)

      if (hero !== EXPECTED_HERO) {
        throw new Error(`hero sentence: expected ${JSON.stringify(EXPECTED_HERO)}, got ${JSON.stringify(hero)}`)
      }
      if (tileCount !== EXPECTED_TILES) {
        throw new Error(`expected ${EXPECTED_TILES} .tile elements, found ${tileCount}`)
      }
      if (consoleErrors.length > 0) {
        throw new Error(`browser console errors: ${consoleErrors.join(' | ')}`)
      }
      ok = true
    } finally {
      await browser.close()
    }
  } catch (err) {
    failure = err
  } finally {
    birdcage.kill()
    rmSync(workDir, { recursive: true, force: true })
  }

  if (!ok) {
    console.error('\nbirdcage log:\n' + birdcageLog)
    console.error(`\nsmoke: FAILED -- ${failure}`)
    process.exit(1)
  }
  console.log('\nsmoke: ok')
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
