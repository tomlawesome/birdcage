#!/usr/bin/env node
// Exercises signin.mjs's own pieces that need no birdcage: the
// authenticator code against RFC 6238 appendix B's SHA-1 vectors (key
// "12345678901234567890", cut to gauntlet's six digits), the setup-code
// reader against birdcage's own log line, the key file's size and
// mode, the log redaction, and the key directory's removal on every way
// out (a real child process for exit, throw, SIGINT and SIGTERM). The
// sign-in itself is proved live by smoke.mjs.
import { spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { base32Decode, hide, redactCodes, redactSecrets, setupCodeFrom, totpCode, writeAuthKeyFile } from './signin.mjs'

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

const unlockLine =
  '12:05:00 WARN  auth     │ sign-in for the admin account "e2e-admin" is disabled after 10 failed attempts in a row, and no other admin can unlock it -- lift the disable with unlock code WXYZ-2345-abcd-6789 (valid until ...'
const redacted = redactCodes(`${line}\n${unlockLine}\n${line}`)
check(/ab12-CD34-ef56-GH78|WXYZ-2345-abcd-6789/.test(redacted), false, 'redaction blanks every setup and unlock code')
check(redacted.split('with setup code <redacted>').length - 1, 2, 'redaction says which kind of code it blanked (setup)')
check(redacted.includes('with unlock code <redacted> (valid until'), true, 'redaction says which kind of code it blanked (unlock)')

const dir = mkdtempSync(join(tmpdir(), 'birdcage-signin-test-'))

// A failed browser call can quote what it was typing: every hidden value
// is blanked from printed text, the app secret also in its spaced groups.
hide('pw-fake-Zq9xLm2')
hide('AAAABBBBCCCCDDDD')
hide('ab12-CD34-ef56-GH78')
hide('')
const quoted = 'fill("pw-fake-Zq9xLm2") failed; secret AAAA BBBB CCCC DDDD; raw AAAABBBBCCCCDDDD; code ab12-CD34-ef56-GH78; port 8080'
const blanked = redactSecrets(quoted)
check(blanked.includes('pw-fake-Zq9xLm2') || blanked.includes('AAAA') || blanked.includes('ab12-CD34'), false, 'redactSecrets blanks every hidden value')
check(blanked.includes('port 8080') && blanked.includes('fill('), true, 'redactSecrets leaves the rest of the text')
check(redactSecrets(new Error('x')).startsWith('Error: x'), true, 'redactSecrets takes any value')
hide('482913')
hide('rc-fake-7k2m')
check(redactSecrets('fill("482913") then rc-fake-7k2m'), 'fill("<redacted>") then <redacted>', 'redactSecrets blanks a typed code and a recovery code')

try {
  const a = writeAuthKeyFile(dir)
  check(readFileSync(a).length, 32, 'the key file holds 32 bytes')
  check(statSync(a).mode & 0o777, 0o400, 'the key file is readable by its owner alone')

  // removeOnExit, in a real Node process per way out: it writes a key
  // into a fresh directory, prints the directory, then leaves the way
  // under test. The directory must be gone afterwards each time.
  const signinURL = new URL('./signin.mjs', import.meta.url).href
  const ways = {
    'a normal exit': ['', 0],
    'process.exit(1)': ['process.exit(1)', 1],
    'an uncaught throw': ["throw new Error('boom')", 1],
    SIGINT: ["process.kill(process.pid, 'SIGINT'); setTimeout(() => {}, 5000)", 130],
    SIGTERM: ["process.kill(process.pid, 'SIGTERM'); setTimeout(() => {}, 5000)", 143],
  }
  for (const [way, [leave, wantStatus]] of Object.entries(ways)) {
    const script = `
      import { mkdtempSync } from 'node:fs'
      import { tmpdir } from 'node:os'
      import { join } from 'node:path'
      import { removeOnExit, writeAuthKeyFile } from ${JSON.stringify(signinURL)}
      const d = mkdtempSync(join(${JSON.stringify(dir)}, 'way-'))
      removeOnExit(d)
      writeAuthKeyFile(d)
      console.log(d)
      ${leave}
    `
    const run = spawnSync(process.execPath, ['--input-type=module', '-e', script], { encoding: 'utf8', timeout: 10000 })
    const made = run.stdout.trim()
    check(made !== '' && run.status === wantStatus, true, `${way}: the child ran and exited ${wantStatus} (got ${run.status})`)
    check(made !== '' && !existsSync(made), true, `${way}: the key directory is removed`)
  }
} finally {
  rmSync(dir, { recursive: true, force: true })
}

process.exit(fail)
