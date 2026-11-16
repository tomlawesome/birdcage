# Sign-in screens: build specification (#8, slice B)

Design: [ADR-0017](../adr/0017-sign-in-door.md). Mock-up to port:
`docs/design/concepts/round-18/direction-an-bars-all-screens.html` with
`door.css`, `door.js`, `bars.js`. Server side: ADR-0016; routes are
gauntlet v0.4.2's (`docs/api/auth.yaml` in that module).

Tests are written from this document alone, before the code.

## Scope

In: the door (every screen in ADR-0017), the API client's sign-in
handling, the signed-in name and its sign-out menu in the shell, a pixel gate for
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
| no passkey refusal shown | `The passkey was not accepted. Try again.` | `register/finish` answers `400` for a refused credential or name |
| no enrolment-on-hold state shown | `Another key is waiting for its codes to be saved. Try again in ten minutes.` | `register/begin` and `totp/enrol` answer `409` while a first factor is on hold (gauntlet holds it ten minutes) |
| no expired-enrolment state shown | `Set-up timed out: the entry you scanned no longer works. Scan this new code.` | `totp/confirm` answers `401 step-expired` once the pending secret runs out; a new one is shown |
| `Passkeys need an https web address.` for every disabled passkey | one line per `passkeys.status` (below) | the server says why: `unset`, `ip` or `insecure` |
| no way out of the second step or the new password | `Sign in as someone else` (owner 31b, 2026-11-15, on #210) | the wrong account, or an account whose only key cannot be made here, would be stuck |

## Seams

All under `frontend/src/`.

### `lib/api.ts`

- `getJSON(path)` is exported and otherwise unchanged for callers. A `401` response also calls the
  handler registered with `onSignedOut(fn)`, then throws `ApiError` as now.
- `sendJSON(method, path, body?)`: sends `X-Requested-With: birdcage`,
  and `Content-Type: application/json` with the JSON body when one is
  given. Returns the parsed JSON of a 2xx. Otherwise throws
  `ApiError` carrying `status` and `kind`: the text after `#` in the
  problem's `type` (`invalid-credentials`, `rate-limited`, `step-expired`,
  `sign-in-required`, `invalid-request`, `conflict`, `setup-required`,
  ...), or `''` when the body is not a problem document; and `detail`.
- Requests never carry credentials in the URL.

### Wire shapes (gauntlet v0.4.2)

- `SessionState`: always `setupRequired`, `ssoAvailable`, `authenticated`,
  `hasLocalPassword`, `ssoConnected`, `mustChangePassword`,
  `mustEnrolSecondFactor`, `mustEnrolPasskey`, `hasTOTP`; when signed in
  `username`, `role`; optional `passkeys {count, status, origin, signIn}`
  (`status` is `ready`, `unset`, `ip` or `insecure`) and `resumable`.
- Login and factor replies: an account `{username, role}`; or
  `{secondFactor: ['passkey'?, 'totp'?]}`; or `{confirm: true}`; or
  `{prove: 'passkey'}`.
- `POST /api/auth/totp/enrol` → `{uri, secret}`;
  `POST /api/auth/totp/confirm` and
  `POST /api/auth/passkeys/register/finish` → `{recoveryCodes: [10] | null, ...}`;
  passkey enrolment begins at `POST /api/auth/passkeys/register/begin`.
- Errors are problem documents; branch on `kind`, never on `detail`.

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

Props: `session: SessionState`, `onenter: (session: SessionState) => void`.
It shows the screen `doorFor(session)` names and moves between screens
as below. It calls `onenter`, once, with the session it read, once the
server says the account is signed in with nothing owed (re-read the
session after every step that could finish sign-in). The password typed
in this visit is dropped on returning to sign in and on entering.

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

### `door/qr.ts`

The QR code comes from `qrcode-generator` (owner approval 29a,
2026-11-15, on #8), until gauntlet serves the pattern itself.

- `qrMatrix(text: string): boolean[][]` — pure; the QR code of `text`
  at error-correction level M, `true` for a dark module. Square, side
  `21 + 4k`. The same text gives the same matrix; different texts differ.
  Each of the three finder corners (top left, top right, bottom left) is
  the standard 7×7 pattern: a dark ring, a light ring, a dark 3×3 centre.
- `drawQR(canvas, text): void` — fills the canvas white, then draws the
  matrix edge to edge in `#06080e`, one `fillRect` per dark module.
- The prove screen shows it in a canvas labelled `QR code` (`aria-label`)
  above the secret.

### `App.svelte`

- On start it reads the session before any dashboard request. It shows
  the door unless `doorFor` is `'in'`; no dashboard route is requested
  while the door is shown. When the door shows, the dashboard data of
  the session before it is dropped, and a reply that left before the
  door showed is not applied.
- A `401` from any dashboard request shows the door again (expired when
  the session says `resumable`, otherwise sign in), remembering the
  account name the tab had.
- The shell's name chip shows the session's `username (role)`, not fixed
  text, and only while signed in.
- **Sign-out** (owner 28a, 2026-11-15). The chip is a button
  (`aria-haspopup="menu"`, `aria-expanded`). Click, Enter or Space opens
  a menu under it, right-aligned, with one item, `Sign out`
  (`role="menuitem"`), which takes focus. Escape or a click outside
  closes it and returns focus to the chip. `Sign out` sends
  `POST /api/auth/logout` through `sendJSON`; on success the door shows
  sign in, the event stream is closed and no further dashboard request
  is made. A `401` means the session is already gone and is treated as
  success. If the request otherwise fails the menu stays open and shows
  `Could not sign out. Try again.` (`role="alert"`). Escape closes the
  menu from the chip as well as from the item, and the menu is closed,
  with no alert, whenever the session is read again. A second click while the
  request is in flight sends nothing. The menu uses the shell's tokens:
  `--raised` surface, 1 px `--hair-2` border, the chip's own type.

## Screens and what they do

Text is exact. Buttons show `Please wait…` and are disabled while their
request is in flight, and after a step that could finish sign-in until
the session has been read again; a second submit in that time sends
nothing. Links that switch mode or screen are disabled for the same time.
Decorative glyphs (the key glyphs, the `▸`) are `aria-hidden`.

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
  It is read only when the door opens on sign in.

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
current step. There is no skip or cancel. The one way out is the link
`Sign in as someone else` (owner 31b): the last link on the choose,
password and both prove screens, below any `… instead` link, as on the
expired screen; it sends `POST /api/auth/logout`, then shows sign in.
The codes screen has no such link: leaving it loses the codes and holds
the key for ten minutes, and `I have saved these` is one press away.

- **Choose.** Heading `Add a second step`; subtitle `Every account needs
  one. Pick a key and prove it works.` Two keys: `Authenticator app` — `A
  code from your phone.`; `Passkey` — `Fingerprint, face or device PIN.`
  The passkey key is disabled unless `passkeys.status` is `ready`, with
  one line in place of its description, by status: `unset` → `No public
  address is set. Passkeys need one.`; `ip` → `The public address is an
  IP. Passkeys need a domain name.`; `insecure` → `The public address is
  http. Passkeys need https.`; any other value → `Passkeys need an https
  web address.` When `mustEnrolPasskey`, only the passkey key is offered;
  if it is disabled, nothing on the screen works, so a message shows
  (`role="alert"`): `This account needs a passkey, and none can be made
  at this address.` The key's line says what to fix; `Sign in as someone
  else` is the way out.
- **Prove it, authenticator.** `POST /api/auth/totp/enrol {password}`
  with the password typed earlier in this visit; if the door does not
  hold one (the page was reloaded), a `password` field is shown first with
  button `Continue`. Then: heading `Prove it works`; subtitle `Scan this
  with your authenticator app, then enter the code it shows.`; the QR of
  `uri` (`door/qr.ts`); `Secret` and the secret in groups of four; field `6-digit code`;
  button `Confirm`; note `Confirming signs this account out everywhere
  else.`; link `Use a passkey instead` (when offered).
  `POST /api/auth/totp/confirm {code}`: codes returned → the codes
  screen; `400` → `Incorrect code.`, field cleared and focused;
  `401 step-expired` → start the step again with a new secret, showing
  `Set-up timed out: the entry you scanned no longer works. Scan this new
  code.`, field cleared. `totp/enrol` `409` → `Another key is waiting
  for its codes to be saved. Try again in ten minutes.` (the same line as
  the passkey's), on the screen the enrolment was started from.
- **Prove it, passkey.** Heading `Prove it works`; subtitle `Name this
  passkey. Your browser asks for the fingerprint, face or PIN.`; field
  `name`; button `Add passkey`, `Waiting…` during the prompt; link `Use an
  authenticator app instead`. `register/begin {password}`, the browser
  prompt, `register/finish {credential, name}`. `register/begin` `409` →
  `Another key is waiting for its codes to be saved. Try again in ten
  minutes.`; `register/finish` `400` → `The passkey was not accepted.
  Try again.`
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
password`, `confirm password`; button `Set password`; below it the link
`Sign in as someone else` (owner 31b) → `POST /api/auth/logout`, then
sign in.
`POST /api/auth/password {newPassword}`; `400` → the server's `detail`.

### Session expired (`'expired'`)

Over the dimmed dashboard. Heading `Session expired`; subtitle `Enter
your password to continue.`; the account name when known; field
`password`; button `Continue`; links `Use your passkey instead` (only
when `passkeys.signIn`) and `Sign in as someone else`. In passkey mode:
heading `Use your passkey`; button `Use your passkey`; links `Use your
password instead` (back to the password, which takes focus) and `Sign in
as someone else`.

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
6. Second step: disabled passkey key, its line for each status; the
   passkey-only account with a disabled key shows the alert; expired
   enrolment shows its line with a new secret; `totp/enrol` 409; `Sign
   in as someone else` signs out first on each screen that has it, and
   the codes screen has none; the reload case asks for the
   password; codes shown in the order sent (use codes not in sorted
   order); `Copy all` writes all ten; nothing is written to
   `localStorage` or `sessionStorage`.
7. Session expired: each response; someone else signs out first.
8. Sign-out menu: opens and closes by mouse and keyboard, focus moves
   as stated, each outcome of the request, double click sends one.
9. `App`: no dashboard request before the session is read; none while
   the door shows; a later `401` shows the door; the chip shows the
   session's name and role.
10. `bars`: `seeded` repeats; `makeTrace` bounds and zeros; `clampOffset`
   limits including the neighbouring case (`barIndex` 2 is not limited to
   36); reduced motion requests no animation frame.

Pixel gate: `npm run compare:door`, in the shape of
`frontend/scripts/band-compare.mjs`, stage `porting`: sign in, first
run, choose, prove, codes and session expired at a frozen moment against
the mock-up at the same `?t=`, the mock-up's bottom-left links hidden.

Live: `frontend/e2e/smoke.mjs` reaches the dashboard through the screens
in Firefox: first run with the setup code from the log, authenticator
app, codes, enter; then sign out from the name menu and sign in again
with a code.
