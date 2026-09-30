#!/usr/bin/env node
// Exercises smoke.mjs's own DATABASE_URL guard directly -- not the smoke
// journey itself, which needs a built birdcage binary, a real Postgres
// and a real browser. Proves the guard refuses a live DATABASE_URL that
// is not marked disposable, before touching anything (no seeding, no
// settings overwrite), and does not block the default (no DATABASE_URL)
// or a marked one.
import { spawn } from 'node:child_process'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))

let fail = 0
function check(cond, label) {
  if (cond) console.log(`ok - ${label}`)
  else {
    console.log(`FAIL - ${label}`)
    fail = 1
  }
}

/** Runs e2e/smoke.mjs with the given extra env, killing it shortly
 * after start -- this tests only the guard at the top of main(), never
 * the full journey (which would need go, a birdcage binary, Postgres
 * and a browser to complete). Returns what it printed before that. */
function runGuard(extraEnv, { unsetDatabaseURL = false } = {}) {
  return new Promise((resolve) => {
    const env = { ...process.env, BIRDCAGE_BIN: '/nonexistent/birdcage', ...extraEnv }
    if (unsetDatabaseURL) delete env.DATABASE_URL
    const child = spawn('node', [join(here, 'smoke.mjs')], { env, stdio: ['ignore', 'pipe', 'pipe'] })
    let stdout = ''
    let stderr = ''
    let done = false
    const finish = (code) => {
      if (done) return
      done = true
      clearTimeout(timer)
      resolve({ code, stdout, stderr })
    }
    child.stdout.on('data', (d) => (stdout += d))
    child.stderr.on('data', (d) => (stderr += d))
    child.on('exit', (code) => finish(code))
    const timer = setTimeout(() => {
      child.kill('SIGKILL')
      finish(null)
    }, 5000)
  })
}

const withoutMarker = await runGuard({ DATABASE_URL: 'postgres://example.invalid/db' })
check(withoutMarker.code === 1, 'refuses a live DATABASE_URL with no disposable marker')
check(withoutMarker.stderr.includes('SMOKE_DATABASE_URL_IS_DISPOSABLE'), 'names the marker on stderr')
check(!withoutMarker.stdout.includes('step'), 'refuses before seeding or settings run')

const withMarker = await runGuard({ DATABASE_URL: 'postgres://example.invalid/db', SMOKE_DATABASE_URL_IS_DISPOSABLE: '1' })
check(withMarker.stdout.includes('seeding'), 'a DATABASE_URL marked disposable is not refused')

const noDatabaseURL = await runGuard({}, { unsetDatabaseURL: true })
check(noDatabaseURL.stdout.includes('seeding'), 'no DATABASE_URL set (SQLite default) is not refused')

process.exit(fail)
