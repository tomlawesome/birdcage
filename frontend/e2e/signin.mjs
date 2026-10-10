// The sign-in the browser journeys share (issue #8, ADR-0016) -- the
// same steps as scripts/e2e/first-admin.sh, which the shell journeys
// use, written for Node so smoke.mjs needs no shell or second runtime:
//
//   1. a sign-in key file birdcage will not start without
//      (BIRDCAGE_AUTH_KEY_FILE): 32 fresh random bytes, readable by the
//      owner alone;
//   2. the first admin, created with the one-time setup code birdcage
//      writes to its log, then an authenticator app enrolled (password
//      accounts must hold a second factor), then a real sign-in with
//      password and code.
//
// What comes back is the signed-in session cookie, for the journey to
// put into the browser before its first page load. The password, the
// app secret, the codes and the recovery codes are made or read here and
// never printed: a failure names the step, the status and the problem
// document's title and detail only, which gauntlet never puts a secret
// in.
import { createHmac, randomBytes } from 'node:crypto'
import { rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

const USERNAME = 'e2e-admin'
// gauntlet's CSRF header: every request that changes something carries it.
const CSRF = { 'X-Requested-With': 'birdcage' }
// birdcage's session cookie; gauntlet adds the __Host- prefix when the
// cookie is Secure (TLS), which this plain-HTTP journey never is.
const SESSION_COOKIE = /^(__Host-)?birdcage_session$/

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
  session() {
    for (const [name, value] of this.#cookies) if (SESSION_COOKIE.test(name)) return { name, value }
    return null
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
 * Creates the first admin with setupCode, enrols an authenticator app,
 * signs in with password and code, and returns { name, value } of the
 * signed-in session cookie. Before creating the admin it checks what
 * only exists then: the API answers 503 "setup required", and a wrong
 * setup code is refused. log(message) reports each step.
 */
export async function signInFirstAdmin(base, setupCode, log = () => {}) {
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

  const password = randomBytes(24).toString('base64url')
  const setup = new Jar()
  expect(
    'POST /api/auth/register',
    await call(base, setup, 'POST', '/api/auth/register', { username: USERNAME, password, setupCode }),
    201,
  )
  log('created the first admin with the logged setup code')

  const enrol = await call(base, setup, 'POST', '/api/auth/totp/enrol', { password })
  expect('POST /api/auth/totp/enrol', enrol, 200)
  const secret = enrol.json?.secret
  if (!secret) throw new Error('sign-in: POST /api/auth/totp/enrol answered no secret')
  const confirm = await call(base, setup, 'POST', '/api/auth/totp/confirm', { code: totpCode(secret, step30()) })
  expect('POST /api/auth/totp/confirm', confirm, 200)
  if (confirm.json?.pendingConfirmation !== true) throw new Error('sign-in: the app was not held for its recovery codes')
  expect('POST /api/auth/recovery-codes/confirm', await call(base, setup, 'POST', '/api/auth/recovery-codes/confirm'), 200)
  log('enrolled an authenticator app and confirmed its recovery codes')

  // A fresh sign-in, as a person makes one. The enrolment spent this
  // step's code, so the next step's (inside gauntlet's one-step window).
  const jar = new Jar()
  const login = await call(base, jar, 'POST', '/api/auth/login', { username: USERNAME, password })
  expect('POST /api/auth/login', login, 200)
  if (!login.json?.secondFactor?.includes('totp')) throw new Error('sign-in: the password step did not ask for the code')
  expect(
    'POST /api/auth/login/factor',
    await call(base, jar, 'POST', '/api/auth/login/factor', { code: totpCode(secret, step30() + 1) }),
    200,
  )
  const session = await call(base, jar, 'GET', '/api/auth/session')
  expect('GET /api/auth/session', session, 200)
  if (!(session.json?.authenticated && session.json?.role === 'admin' && !session.json?.mustEnrolSecondFactor)) {
    throw new Error('sign-in: signed in, but the session is not a usable admin one')
  }
  const cookie = jar.session()
  if (!cookie) throw new Error('sign-in: signed in, but no session cookie came back')
  log('signed in with password and authenticator code')
  return cookie
}
