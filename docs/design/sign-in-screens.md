# Sign-in screens: build specification (#8, slice B)

Design: [ADR-0017](../adr/0017-sign-in-door.md). Mock-up to port:
`docs/design/concepts/round-18/direction-an-bars-all-screens.html` with
`door.css`, `door.js`, `bars.js`. Server side: ADR-0016; routes are
gauntlet v0.4.2's (`docs/api/auth.yaml` in that module).

Tests are written from this document alone, before the code.

## Scope

In: the door (every screen in ADR-0017), the API client's sign-in
handling, the signed-in name and sign-out in the shell, a pixel gate for
the door, and the browser smoke signing in through the screens.

Out, each needing its own design first: users, API tokens, password
change, and managing passkeys or the authenticator app after sign-in
(ADR-0016 decision 11). Held and confirmed sign-ins stay on #189.

## Where the mock-up cannot be true

The server does not report these, so the built text differs from the
mock-up. These are the only intended differences.

| Mock-up | Built | Why |
|---|---|---|
| `Incorrect account or password. 4 attempts left.` | `Incorrect account or password.` | no attempts count is sent |
| `Too many attempts. Try again at 09:23.` with dashed, dead fields | `Too many attempts. Try again later.`; fields stay usable | no end time is sent |
| `Passkey and SSO sign-in still work.` | `SSO sign-in still works.`, only when SSO is on | passkey-alone sign-in is off |
| `Signed out at 08:52 after an hour unused. Enter your password to continue.` | `Enter your password to continue.` | no time is sent |
| account name under `Session expired` | shown only if this tab knew it | not sent once timed out |

## Seams

All under `frontend/src/`.

### `lib/api.ts`

- `getJSON(path)` unchanged for callers. A `401` response also calls the
  handler registered with `onSignedOut(fn)`, then throws `ApiError` as now.
- `sendJSON(method, path, body?)`: sends `X-Requested-With: birdcage`,
  and `Content-Type: application/json` with the JSON body when one is
  given. Returns the parsed JSON of a 2xx. Otherwise throws
  `ApiError` carrying `status` and `kind`: the text after `#` in the
  problem's `type` (`invalid-credentials`, `rate-limited`, `step-expired`,
  `sign-in-required`, `invalid-request`, `conflict`, `setup-required`,
  ...), or `''` when the body is not a problem document; and `detail`.
- Requests never carry credentials in the URL.

### `lib/auth.ts`

- `readSession(): Promise<SessionState>` — `GET /api/auth/session`.
- `doorFor(s: SessionState): Door` — pure. First match wins:
  1. `setupRequired` → `'firstrun'`
  2. `authenticated && mustChangePassword` → `'newpassword'`
  3. `authenticated && (mustEnrolSecondFactor || mustEnrolPasskey)` → `'choose'`
  4. `authenticated` → `'in'`
  5. `resumable` → `'expired'`
  6. otherwise → `'signin'`

### `door/Door.svelte`

Props: `session: SessionState`, `onenter: () => void`. It shows the screen
`doorFor(session)` names and moves between screens as below. It calls
`onenter` once the server says the account is signed in with nothing
owed (re-read the session after every step that could finish sign-in).

### `door/bars.ts`

- `seeded(seed: number): () => number` — deterministic, values in [0, 1).
- `makeTrace(rnd, length, reach): Float32Array` — the sharp trace: every
  value within ±(3 + `reach`); at least a third of the values are exactly 0;
  the same `rnd` sequence gives the same trace.
- `clampOffset(v, barIndex, side): number` — never beyond ±62; for
  `barIndex === 1` (the bar next to an amber post) never more than 36
  towards the form (`side` is −1 left of the form, +1 right; towards the
  form means `v * side < 0`).
- `startBars(canvas, opts?): () => void` — draws and animates; returns a
  stop function. `opts.frozenAt` (seconds) runs the simulation that long
  from seed 20261115 and draws one frame with no animation loop. Under
  `prefers-reduced-motion: reduce` it draws still bars and requests no
  animation frame.
- `CAUGHT_SHARE = 0.27`: the share of pulses that are caught.

### `App.svelte`

- On start it reads the session before any dashboard request. It shows
  the door unless `doorFor` is `'in'`; no dashboard route is requested
  while the door is shown.
- A `401` from any dashboard request shows the door again (expired when
  the session says `resumable`, otherwise sign in), remembering the
  account name the tab had.
- The shell's name chip shows the session's `username (role)`, not fixed
  text. Sign-out: see "Open".

## Screens and what they do

Text is exact. Buttons show `Please wait…` and are disabled while their
request is in flight; a second submit in that time sends nothing.

### Sign in (`'signin'`)

Fields with placeholders `account`, `password`; button `Enter`. When
`ssoAvailable`: a divider `or` and a link `Sign in with SSO` to
`/api/auth/oidc/login`; otherwise neither is shown.

- Empty account: `Enter your account name.` Empty password: `Enter your
  password.` Nothing is sent.
- `POST /api/auth/login {username, password}`:
  - account → re-read session, continue by `doorFor`.
  - `secondFactor` challenge → the code step.
  - `401 invalid-credentials` → `Incorrect account or password.`; the
    password field is cleared and focused; the account field keeps its
    value. The same text whether or not the account exists.
  - `429` → `Too many attempts. Try again later.`, plus `SSO sign-in still
    works.` when `ssoAvailable`.
  - anything else (including a `confirm` challenge, #189) → `Sign-in
    failed. Try again.`
- Messages have `role="alert"` and are never red.
- A page opened with `?ssoError=<code>` shows, above the form:
  `not_permitted` → `Your account signed in but is not permitted to use
  this birdcage.`; any other code → `SSO sign-in failed. Try again, or
  sign in with your password.` The query is then removed from the address.

### Code step

Shown after a `secondFactor` challenge. Which parts show depends on the
list: `totp`, `passkey`, or both.

- With `totp`: heading `Enter your code`; subtitle `Your password was
  right. Enter the current code from your authenticator app to finish
  signing in.`; field placeholder `6-digit code`; button `Continue`;
  links `Use your passkey instead` (only with `passkey`) and `Use a
  recovery code instead`.
- Recovery mode: subtitle `Your password was right. Enter one of your
  recovery codes to finish signing in.`; placeholder `recovery code`;
  link `Use your authenticator app instead`.
- Passkey mode (or `passkey` only): heading `Use your passkey`; subtitle
  `Your password was right. Use your passkey to finish signing in.`;
  button `Use your passkey`, `Waiting…` during the browser prompt.
  `POST /api/auth/login/factor/begin`, the browser's passkey prompt, then
  `POST /api/auth/login/factor {assertion}`.
- Empty code: `Enter the code from your app.` / `Enter a recovery code.`
- `POST /api/auth/login/factor {code}`: account → re-read session and
  continue; a `prove` challenge → passkey mode using
  `/api/auth/login/prove/begin` and `/api/auth/login/prove`;
  `401 invalid-credentials` → `Incorrect code.`, field cleared;
  `401 step-expired` → back to sign in with `Your sign-in timed out.
  Enter your password again.`; `429` → `Too many attempts. Try again
  later.`

### First run (`'firstrun'`)

Heading `Create the admin account`; subtitle `No account exists yet. The
setup code is in the server log.`; fields `setup code`, `account`,
`password`, `confirm password`; button `Create account`.

- Checks, first failure only, nothing sent: `Enter the setup code.`,
  `Enter your account name.`, `Enter your password.`, `Type the password a
  second time to confirm it.`, `Passwords do not match.`
- `POST /api/auth/register {username, password, setupCode}`: created →
  re-read session and continue (normally to the second step);
  `401` → `Incorrect setup code.`; `400` → the server's `detail`;
  `409` → re-read session and continue; `429` → `Too many attempts. Try
  again later.`

### Add a second step (`'choose'`, then prove, then codes)

A thread line `choose · prove it · keep the codes · enter` marks the
current step. There is no skip, cancel or sign-out here.

- **Choose.** Heading `Add a second step`; subtitle `Every account needs
  one. Pick a key and prove it works.` Two keys: `Authenticator app` — `A
  code from your phone.`; `Passkey` — `Fingerprint, face or device PIN.`
  The passkey key is disabled, with `Passkeys need an https web address.`
  in place of its description, unless `passkeys.status` is `ready`. When
  `mustEnrolPasskey`, only the passkey key is offered.
- **Prove it, authenticator.** `POST /api/auth/totp/enrol {password}`
  with the password typed earlier in this visit; if the door does not
  hold one (the page was reloaded), a `password` field is shown first with
  button `Continue`. Then: heading `Prove it works`; subtitle `Scan this
  with your authenticator app, then enter the code it shows.`; the QR of
  `uri`; `Secret` and the secret in groups of four; field `6-digit code`;
  button `Confirm`; note `Confirming signs this account out everywhere
  else.`; link `Use a passkey instead` (when offered).
  `POST /api/auth/totp/confirm {code}`: codes returned → the codes
  screen; `400` → `Incorrect code.`; `401 step-expired` → start the step
  again with a new secret.
- **Prove it, passkey.** Heading `Prove it works`; subtitle `Name this
  passkey. Your browser asks for the fingerprint, face or PIN.`; field
  `name`; button `Add passkey`, `Waiting…` during the prompt; link `Use an
  authenticator app instead`. `register/begin {password}`, the browser
  prompt, `register/finish {credential, name}`.
- **Keep the codes.** Heading `Keep the codes`; subtitle `Ten recovery
  codes. Each works once in place of your second step. They are not shown
  again.`; the ten codes in two columns, in the order sent; `Copy all`
  (becomes `Copied`), `Download` (a text file, one code per line); button
  `I have saved these` → `POST /api/auth/recovery-codes/confirm`, re-read
  session, continue. The codes are held in memory only: never in storage,
  the address or the log.

### Set a new password (`'newpassword'`)

Mikroview's screen: heading `Set a new password`; subtitle `Your one-time
code got you in. Choose a password only you know.`; fields `new
password`, `confirm password`; button `Set password`.
`POST /api/auth/password {newPassword}`; `400` → the server's `detail`.

### Session expired (`'expired'`)

Over the dimmed dashboard. Heading `Session expired`; subtitle `Enter
your password to continue.`; the account name when known; field
`password`; button `Continue`; links `Use your passkey instead` (only
when `passkeys.signIn`) and `Sign in as someone else`.

- `POST /api/auth/reauthenticate {password}`: account → `onenter`;
  `401 invalid-credentials` → `Incorrect password.`;
  `401 sign-in-required` → the sign-in screen; `429` as above.
- `Sign in as someone else` → `POST /api/auth/logout`, then sign in.

### Entering

When sign-in completes the two halves of the bars slide apart over
700 ms and the dashboard shows between them; under reduced motion the
door is simply replaced.

## Tests

Vitest, in the shape of `frontend/src/Tiles.svelte.test.ts`, with `fetch`
stubbed. Each behaviour above is tested from
what the user sees (text, roles, focus) and what is sent (method, path,
headers, body). In particular:

1. `doorFor`: one case per rule, and that an earlier rule wins over a
   later one (e.g. `setupRequired` with `authenticated`).
2. `sendJSON`: the header on every method; `kind` from a problem body and
   from a non-problem body; `getJSON` 401 calls the handler once.
3. Sign in: each response above; the refusal text is identical for
   `401` whatever `detail` says; SSO parts absent when `ssoAvailable` is
   false; double submit sends one request.
4. Code step: each mode's text and links for `[totp]`, `[passkey]`,
   `[totp, passkey]`; wrong code; step expired.
5. First run: each check in order; each response.
6. Second step: disabled passkey key; the reload case asks for the
   password; codes shown in the order sent (use codes not in sorted
   order); `Copy all` writes all ten; nothing is written to
   `localStorage` or `sessionStorage`.
7. Session expired: each response; someone else signs out first.
8. `App`: no dashboard request before the session is read; none while
   the door shows; a later `401` shows the door; the chip shows the
   session's name and role.
9. `bars`: `seeded` repeats; `makeTrace` bounds and zeros; `clampOffset`
   limits including the neighbouring case (`barIndex` 2 is not limited to
   36); reduced motion requests no animation frame.

Pixel gate: `npm run compare:door`, in the shape of
`frontend/scripts/band-compare.mjs`, stage `porting`: sign in, first
run, choose, prove, codes and session expired at a frozen moment against
the mock-up at the same `?t=`, the mock-up's bottom-left links hidden.

Live: `frontend/e2e/smoke.mjs` reaches the dashboard through the screens
in Firefox: first run with the setup code from the log, authenticator
app, codes, enter; then sign out, sign in with a code.

## Open

- **QR code.** Drawing one needs a library birdcage has not approved.
  Until the owner chooses, the prove screen is built without the QR
  square (secret only) and is not done.
- **Sign-out.** No mock-up shows where it lives. Until the owner
  chooses, the chip shows the name only and the live journey's sign-out
  step waits.
