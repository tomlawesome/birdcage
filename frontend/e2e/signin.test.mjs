#!/usr/bin/env node
// Exercises signin.mjs's own pieces that need no birdcage: the
// authenticator code against RFC 6238 appendix B's SHA-1 vectors (key
// "12345678901234567890", cut to gauntlet's six digits), the setup-code
// reader against birdcage's own log line, and the key file's size and
// mode. The sign-in itself is proved live by smoke.mjs.
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { base32Decode, setupCodeFrom, totpCode, writeAuthKeyFile } from './signin.mjs'

let fail = 0
function check(actual, want, label) {
  if (actual === want) console.log(`ok - ${label}`)
  else {
    console.log(`FAIL - ${label}: expected ${JSON.stringify(want)} got ${JSON.stringify(actual)}`)
    fail = 1
  }
}

const RFC_VECTOR = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
check(base32Decode(RFC_VECTOR).toString(), '12345678901234567890', 'base32 decodes the RFC key')
for (const [t, want] of [
  [59, '287082'],
  [1111111109, '081804'],
  [1111111111, '050471'],
  [1234567890, '005924'],
  [2000000000, '279037'],
  [20000000000, '353130'],
]) {
  check(totpCode(RFC_VECTOR, Math.floor(t / 30)), want, `RFC 6238 SHA-1 vector at T=${t}`)
}
check(totpCode(RFC_VECTOR.toLowerCase() + '====', 1), '287082', 'case and padding are ignored')

const line =
  '12:00:00 WARN  auth     │ no account exists yet -- create the first admin with setup code ab12-CD34-ef56-GH78 (valid until an account exists or this process restarts)'
check(setupCodeFrom(`starting\n${line}\nserving`), 'ab12-CD34-ef56-GH78', 'the setup code is read from the log line')
check(setupCodeFrom('starting\nserving'), null, 'no setup code before birdcage logs one')

const dir = mkdtempSync(join(tmpdir(), 'birdcage-signin-test-'))
try {
  const a = writeAuthKeyFile(dir)
  check(readFileSync(a).length, 32, 'the key file holds 32 bytes')
  check(statSync(a).mode & 0o777, 0o400, 'the key file is readable by its owner alone')
} finally {
  rmSync(dir, { recursive: true, force: true })
}

process.exit(fail)
