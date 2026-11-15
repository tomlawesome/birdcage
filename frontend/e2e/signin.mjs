// The sign-in the browser journeys share (issue #8, ADR-0016) -- the
// same steps as scripts/e2e/first-admin.sh, which the shell journeys
// use, written for Node so smoke.mjs needs no shell or second runtime:
//
//   1. a sign-in key file birdcage will not start without
//      (BIRDCAGE_AUTH_KEY_FILE): 32 fresh random bytes, readable by the
//      owner alone;
//   2. the checks only true before the first admin exists (the API
//      answers 503 setup required; a wrong setup code is refused);
//   3. the first admin through the sign-in screens (issue #8 slice B):
//      first run with the one-time setup code birdcage writes to its
//      log, the authenticator app (password accounts must hold a second
//      factor), the recovery codes, enter;
//   4. sign out from the name menu, and sign in again with the password
//      and a code from the same authenticator app.
//
// The password, the app secret, the codes and the recovery codes are
// made or read here and never printed: a failure names the step, the
// status and the problem document's title and detail only, which
// gauntlet never puts a secret in. A browser call that fails can still
// quote what it was typing (a Playwright fill's call log), so every
// secret is registered with hide() the moment it exists, and whatever
// the journeys print goes through redactSecrets() first.
import { createHmac, randomBytes } from 'node:crypto'
import { rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

const USERNAME = 'e2e-admin'
// gauntlet's CSRF header: every request that changes something carries it.
const CSRF = { 'X-Requested-With': 'birdcage' }

/** Writes a fresh 32-byte sign-in key into dir, mode 0400, and returns
 * its path. The bytes go straight from the random source to the file. */
export function writeAuthKeyFile(dir) {
  const path = join(dir, 'auth.key')
  writeFileSync(path, randomBytes(32), { mode: 0o400 })
  return path
}

/** Removes dir (and the sign-in key in it) on every way out the process
 * can handle: a normal exit, process.exit after an error, and SIGINT or
 * SIGTERM, which would otherwise end Node without running any cleanup.
 * A signal exits with 128 + its number, as a shell reports it. proc is
 * process, or a stand-in for the tests. Returns the cleanup, which is
 * safe to call more than once. */
export function removeOnExit(dir, proc = process) {
  const remove = () => rmSync(dir, { recursive: true, force: true })
  proc.on('exit', remove)
  for (const [signal, number] of [['SIGINT', 2], ['SIGTERM', 15]]) {
    proc.on(signal, () => {
      remove()
      proc.exit(128 + number)
    })
  }
  return remove
}

/** birdcage's log with the one-time setup and unlock codes blanked: the
 * setup code makes whoever reads it the first admin, and the unlock code
 * (logged after repeated failed admin sign-ins) lifts that admin's
 * disable. Same pattern as scripts/e2e/stack.sh's birdcage_log. */
export function redactCodes(log) {
  return log.replace(/with (setup|unlock) code [A-Za-z0-9-]+/g, 'with $1 code <redacted>')
}

/** The setup code from birdcage's log line ("... with setup code
 * XXXX-XXXX-XXXX-XXXX (valid until ..."), or null when it is not there
 * yet. */
export function setupCodeFrom(log) {
  return /with setup code ([A-Za-z0-9-]+)/.exec(log)?.[1] ?? null
}

/** Decodes RFC 4648 base32 (either case; padding and spaces ignored). */
export function base32Decode(text) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const clean = text.toUpperCase().replace(/[=\s]/g, '')
  let buf = 0
  let bits = 0
  const out = []
  for (const ch of clean) {
    const v = alphabet.indexOf(ch)
    if (v < 0) throw new Error('not base32')
    // Only the bits not yet written out are kept (at most 12), so the
    // buffer never outgrows a 32-bit integer however long the secret.
    buf = ((buf << 5) | v) & 0x1fff
    bits += 5
    if (bits >= 8) {
      bits -= 8
      out.push((buf >> bits) & 0xff)
    }
  }
  return Buffer.from(out)
}

/** The RFC 6238 code (HMAC-SHA1, six digits) for a 30-second counter. */
export function totpCode(secretBase32, counter) {
  const msg = Buffer.alloc(8)
  msg.writeBigUInt64BE(BigInt(counter))
  const mac = createHmac('sha1', base32Decode(secretBase32)).update(msg).digest()
  const off = mac[mac.length - 1] & 0x0f
  const value = (mac.readUInt32BE(off) & 0x7fffffff) % 1000000
  return String(value).padStart(6, '0')
}

const step30 = () => Math.floor(Date.now() / 1000 / 30)

// Every secret value this run has made or read (hide()).
const hidden = new Set()

/** Registers value as never to be printed; returns it. */
export function hide(value) {
  if (typeof value === 'string' && value.length >= 4) hidden.add(value)
  return value
}

/** text with every hidden value (and, for an app secret, its spaced
 * groups of four as the screen shows it) replaced by <redacted>. */
export function redactSecrets(text) {
  let out = String(text)
  for (const v of [...hidden].sort((a, b) => b.length - a.length)) {
    out = out.split(v).join('<redacted>')
    const grouped = v.match(/.{1,4}/g)?.join(' ')
    if (grouped && grouped !== v) out = out.split(grouped).join('<redacted>')
  }
  return out
}

/** A minimal cookie jar: name -> value, honouring deletions. */
class Jar {
  #cookies = new Map()
  take(res) {
    for (const line of res.headers.getSetCookie()) {
      const [pair, ...attrs] = line.split(';')
      const eq = pair.indexOf('=')
      const name = pair.slice(0, eq).trim()
      const value = pair.slice(eq + 1).trim()
      const expired = attrs.some((a) => {
        const [k, v = ''] = a.trim().split('=')
        if (k.toLowerCase() === 'max-age') return Number(v) <= 0
        if (k.toLowerCase() === 'expires') return Date.parse(v) <= Date.now()
        return false
      })
      if (expired || value === '') this.#cookies.delete(name)
      else this.#cookies.set(name, value)
    }
  }
  header() {
    return [...this.#cookies].map(([k, v]) => `${k}=${v}`).join('; ')
  }
}

async function call(base, jar, method, path, body) {
  const headers = { Cookie: jar.header() }
  if (method !== 'GET') Object.assign(headers, CSRF, { 'Content-Type': 'application/json' })
  const res = await fetch(base + path, {
    method,
    headers,
    body: method === 'GET' ? undefined : JSON.stringify(body ?? {}),
    redirect: 'manual',
  })
  jar.take(res)
  let json = null
  try {
    json = await res.json()
  } catch {
    // not JSON: the status alone is reported
  }
  return { status: res.status, json }
}

function expect(what, res, want) {
  if (res.status !== want) {
    const p = res.json ?? {}
    const why = [p.title, p.detail].filter(Boolean).join(': ') || '(no problem document)'
    throw new Error(`sign-in: ${what} answered ${res.status}, want ${want} -- ${why}`)
  }
}

/**
 * Checks what only exists before the first admin: the API answers 503
 * "setup required", and a wrong setup code is refused. log(message)
 * reports each step.
 */
export async function checkBeforeFirstAdmin(base, log = () => {}) {
  const anon = new Jar()
  const before = await call(base, anon, 'GET', '/api/alerts')
  expect('GET /api/alerts before any admin exists', before, 503)
  if (before.json?.title !== 'Setup required') throw new Error('sign-in: the 503 before setup is not "setup required"')
  log('before the first admin, GET /api/alerts answers 503 setup required')

  const wrong = await call(base, anon, 'POST', '/api/auth/register', {
    username: USERNAME,
    password: 'a-password-never-used',
    setupCode: 'not-the-setup-code',
  })
  expect('POST /api/auth/register with a wrong setup code', wrong, 401)
  log('a wrong setup code is refused (401)')
}

/**
 * Signs in through the door's screens in page (a Playwright page already
 * on birdcage's address, showing first run): creates the first admin
 * with setupCode, picks the authenticator app, proves it with the code
 * for the secret the screen shows, keeps the recovery codes, and waits
 * for the dashboard. The password is made here and typed only into the
 * page; nothing secret is printed. log(message) reports each step.
 * Returns the account for signInAgain: its name, password, app secret
 * and the time step of the last code used.
 */
export async function firstAdminThroughScreens(page, setupCode, log = () => {}) {
  const password = hide(randomBytes(24).toString('base64url'))
  hide(setupCode)
  await page.waitForSelector('h1:text-is("Create the admin account")', { timeout: 10000 })
  await page.fill('input[placeholder="setup code"]', setupCode)
  await page.fill('input[placeholder="account"]', USERNAME)
  await page.fill('input[placeholder="password"]', password)
  await page.fill('input[placeholder="confirm password"]', password)
  await page.click('button:has-text("Create account")')
  await page.waitForSelector('h1:text-is("Add a second step")', { timeout: 10000 })
  log('first run: created the first admin with the logged setup code')

  await page.click('button.key:has-text("Authenticator app")')
  const secret = hide(((await page.locator('.secret').textContent({ timeout: 10000 })) ?? '').replace(/\s+/g, ''))
  if (!secret) throw new Error('sign-in: the prove screen showed no secret')
  if (!(await page.locator('canvas.qr[aria-label="QR code"]').isVisible())) throw new Error('sign-in: the prove screen showed no QR code')
  const counter = step30()
  await page.fill('input[placeholder="6-digit code"]', totpCode(secret, counter))
  await page.click('button:has-text("Confirm")')
  await page.waitForSelector('.grid span', { timeout: 10000 })
  const codes = await page.locator('.grid span').count()
  if (codes !== 10) throw new Error(`sign-in: the codes screen showed ${codes} recovery codes, want 10`)
  log('second step: proved an authenticator app, shown ten recovery codes')

  await page.click('button:has-text("I have saved these")')
  await page.waitForSelector('.door', { state: 'detached', timeout: 10000 })
  log(`entered: the door opened onto the dashboard as ${USERNAME}`)
  return { username: USERNAME, password, secret, counter }
}

/**
 * Signs out from the name menu in page, then signs in again through the
 * screens with the account's password and a code from its authenticator
 * app, and waits for the dashboard. gauntlet refuses a code whose time
 * step is not after the last one used and accepts one step either side
 * of now, so the code is for the later of now and the step after the
 * last. Returns the account with that step recorded.
 */
export async function signInAgain(page, account, log = () => {}) {
  await page.click('.status button.who')
  await page.click('[role="menuitem"]:has-text("Sign out")')
  await page.waitForSelector('input[placeholder="account"]', { timeout: 10000 })
  log('signed out from the name menu: the door shows sign in')

  await page.fill('input[placeholder="account"]', account.username)
  await page.fill('input[placeholder="password"]', account.password)
  await page.click('button:has-text("Enter")')
  await page.waitForSelector('h1:text-is("Enter your code")', { timeout: 10000 })
  const counter = Math.max(step30(), account.counter + 1)
  await page.fill('input[placeholder="6-digit code"]', totpCode(account.secret, counter))
  await page.click('button:has-text("Continue")')
  await page.waitForSelector('.door', { state: 'detached', timeout: 10000 })
  log(`signed in again with the password and an authenticator code, as ${account.username}`)
  return { ...account, counter }
}
