# Design round 10 — smoked glass, part of birdcage (#8, slice B)

2026-11-15. Round 9's verdict: "7A is the best but it doesn't hugely tie
in with the rest of birdcage." S, smoked glass, is carried forward.
This round keeps what S is — frosted panes on hinges in a lit room,
depth, grain, door-to-door motion — and makes it the door to this
dashboard rather than a separate product. Three directions, each a
different answer to where the glass and the ratified shell (ADR-0004,
round 6 M; round 7 O) meet. None adds a logo, a bird, or decorative
trace lines on the glass; the tie-in is structural in each case.

The owner's bar for the round: considered, elegant, exceptional; not
cheesy, not generic, not clumsy. The copy is rewritten in the register of
a professional security UI: conventional labels and headings, messages
that give the fact and the next step, no commentary on the page.

## The problem

Unchanged from rounds 8 and 9: one or a few admins sign in to a
dashboard whose good state is nothing happening. The door carries the
whole gauntlet and shows nothing the cage has seen until the visitor is
through. Round 9 made it worth looking at; this round makes it
recognisably birdcage's.

## Shared by every direction

- The ratified base is carried verbatim: palette roles (`--void`,
  `--ink`, `--ink-2`, `--ink-3`, `--accent`, `--ok`, `--now`, the four
  lane colours), mono for data and sans for prose, the wordmark and
  version in the chrome. Amber means "now" and nothing else.
- The shell's geometry is the door's geometry. The trace's band runs
  from x = 190 to x = 1368 at y = 300; the brink stands at 1368; the
  gutter at the left starts at 54. Every direction places the glass
  against those lines and the hand-over frame is the real quiet shell
  (`Quiet for 14 days.`), not a sketch of it.
- Passed panes are green-edged glass with a tick and the step's name;
  panes ahead are dashed grey, the way a silent canary tile is drawn.
  Round 9's barred "cage" pane is removed from all three: the cage is
  what the hand-over shows, not a bar pattern on glass.
- A refusal is ink, never alarm. The refused door turns to ink; the
  paused door is dashed.
- Nothing the cage has seen is shown before sign-in. The only data on
  the page is the visitor's own address, the version and the time. X's
  silhouettes are fixed geometry (see below). The QR square is a
  deterministic placeholder pattern, not a real key; the page does not
  say so, this README does.
- Session rules as in round 9: one hour unused ends a session, one day
  ends it regardless; within the day a timed-out session resumes with
  the password alone or a passkey (owner, 2026-11-14, 5a); the full
  sign-in with the second factor is due again by Sunday 07:31.
- The limiter is ADR-0016's: five refusals per name and per address in
  five minutes; passkey and SSO are not counted. The page never confirms
  whether a username exists and never names another account.
- The door's one primary button is filled in `--accent`; everything else
  is an outlined pill or a bare link. Decided, see below.

## Directions

| Letter | Name | Where the glass meets the shell |
| --- | --- | --- |
| V | the column | The door occupies the trace's column exactly: left edge at the band's first tick (190), right edge at the brink (1368), top at the band's height. Passed panes fold into the gutter where the canary labels will sit; panes ahead stand in the deck's column at the right edge, in the deck's sideways type. The hand-over draws the four band lines across the space the door occupied. |
| W | the brink | The brink is the one element the door and the dashboard share. It stands in the room at 1368 for the whole gauntlet, with a quarter-hour axis under it (ticks and `15 M`, no caption) and `NOW · hh:mm:ss` in amber mono, and carries each scene's time. The doors hang in front of it. At the hand-over the brink shortens to the band's height, the label moves up to the band, and the lines draw across to meet it. In the timed-out scene the frozen page's own brink (`NOW · 08:52:10`) is the only one shown. |
| X | through the frost | What is behind the glass is the shell's light, not its data: the heading, the sub-line, the band, the four tiles and the brink as blurred shapes at their real positions. Each door passed lowers the door's blur (`--lit` rises from .45 towards 1), so the room comes into focus as the visitor goes. At the hand-over the blur goes to zero and the shapes are the page. |

## Scenes (every direction proves all eight, same data)

1. **Sign in** — username and password; `Sign in`, `Use a passkey`,
   `Sign in with SSO`. One pane ahead: `Authentication code`.
2. **Second factor** — `Enter your authentication code`; code half
   typed; `This code is valid for another 19 s.`; `Use a recovery code`;
   `Last sign-in: Thu 13 Nov, 09:41`. One pane passed: `Password`.
3. **First run** — `Create the first administrator`, step 1 of 3; the
   server-log line with the setup code; setup code, username, password,
   confirm password; `Create administrator`, `Sign in with SSO instead`.
   Two panes ahead.
4. **Enrol an authenticator** — QR, key, `Code from the app`, `Confirm`;
   `The key is shown once.` One passed, one ahead.
5. **Recovery codes** — ten codes; `Continue`, `Copy`, `Download`,
   `Print`; `10 codes · none used`. Two passed, none ahead.
6. **Session expired** — over the dimmed dashboard frozen at 08:52:10:
   `Your session expired at 08:52 after an hour of inactivity. Enter
   your password to continue. A full sign-in, including your
   authentication code, is required again by Sunday 07:31.` Password; `A passkey can also be
   used.`; `Continue`, `Sign in as a different user`. One passed pane,
   `Signed in 07:31`.
7. **Refused** — `Incorrect username or password. · 4 attempts left`,
   the door in ink.
8. **Too many attempts** — `Sign-in for this username from 192.0.2.10
   is paused after 5 failed attempts. Try again at 09:23.`; the countdown
   `4:12 until 09:23:00`; the fields dashed; `Passkey and SSO sign-in
   are not paused.`

## Data story

`ada`, an administrator, at the door from 192.0.2.10 on Sat 14 Nov,
birdcage 0.2.0. Scene times run 09:18:04 to 09:18:48. Last sign-in Thu
13 Nov 09:41. The dashboard behind the timed-out door is the quiet
14-day view, frozen at 08:52:10. No other account is named anywhere.

## What each effect costs to build (Svelte + CSS, no WebGL)

- **Hinge motion** (all three): `perspective`, `rotateY`, `translateZ`
  keyframes on a `{#key step}` block. Cheap; one afternoon, as round 9.
  Reduced motion swaps it for a cross-fade and a complete still.
- **Frosted glass** (all three): `backdrop-filter: blur()`. Cheap in
  CSS; the one paint cost is a blurred pane over an animating backdrop.
  V and W keep the backdrop static. X animates the blur radius itself
  (`blur(calc(28px - 14px * var(--lit)))`), which repaints the door on
  each step change only, not per frame.
- **Grain**: inline SVG `feTurbulence` data URI as `mask-image`, as
  round 9. Hours, not days.
- **V's band draw-in**: `clip-path: inset(0 100% 0 0 → 0)` on the band
  SVG, 12 s loop in the mock-up, about 1.2 s in the build. Cheap.
- **W's brink**: one absolutely positioned 2px element with a faint
  gradient halo; the hand-over animates its `top` and `height` and the
  label's `top`. Cheap. The axis is a row of 1px ticks.
- **X's silhouettes**: five or six blurred `div`s at fixed coordinates,
  `filter: blur(18–26px)`, alpha scaled by `--lit`. Cheap. The
  coordinates are the shell's layout constants, so nothing is derived
  from data: the tiles are four regardless of how many canaries exist,
  the band is one bar regardless of what it shows. That is how the
  pre-sign-in page reveals nothing.
- **Sideways pane labels**: `writing-mode: sideways-lr`. Firefox and
  Chromium support it; Safari needs `vertical-rl` plus `rotate(180deg)`.
- Nothing needs JavaScript beyond the step state Svelte already holds.

## Capture

`python3 gen.py`; `node capture.mjs` → `shots/<letter>-<scene>.jpg`,
`<letter>-motion.jpg` (door two landed, 4.9 s), `<letter>-motion-handover.jpg`
(the shell's first view, 10.2 s) and `<letter>-motion-still.jpg` (reduced
motion). 1440×900 at device scale 2, JPEG quality 90, 33 shots, all
inspected, four passes.

Fixed between passes: the glass material was missing from every scene
(the material CSS is keyed on `.g`, which the scene wrapper lacked); X's
silhouettes read as bright smudges (alphas lowered, heading block
tightened, brink narrowed); V's cage pane sat on top of the panes ahead
and their labels collided (cage pane removed in all three; the deck
column is left to the panes ahead); V's two panes ahead in first run
overlapped each other (the first-run door is 1096 wide instead of 1178,
the panes 56 px apart); V's motion page put the passed pane at the left
edge (its `--i` was unset, so the `calc()` fell to `auto`); X's
timed-out pane stood in the middle of the page over a canary tile (the
timed-out layout is now W's: door at the left, pane in the gutter); W's
timed-out scene showed two `NOW` labels (the room's is hidden; the frozen
page's own brink is the one shown); the motion captions and the
reduced-motion tag carried design commentary (reduced to the direction's
name).

Fixed after the coordinator's review of the committed shots: W's axis
carried the band's caption `the last quarter hour, stretched` (removed;
the axis is ticks and `15 M`); the session-expired text said how old
the page behind the door was (sentence cut in all three; the dimmed
page says it); the direction pill sat on the dashboard's footer in the
hand-over frame (the pill fades with the chrome once the shell is in);
V's two passed panes in the recovery-codes scene overlapped and clipped
each other's labels (56 px apart, as the panes ahead).

## Decided

- **Filled primary button, on the door only** (owner, 2026-11-15, 4a).
  The shell's pills stay outlined.
- **The dimmed dashboard stays behind the timed-out door** (owner,
  2026-11-15, 10a).
- **Copy register** (owner, 2026-11-15): conventional security-UI
  labels and messages; no personification, metaphor, second-person
  narration or commentary on the page. The scene tag at the foot of
  each mock-up stays; it is the round's label, not product copy.
- **Round 9's barred cage pane is removed** in all three directions
  (designer, this round). The cage is shown by the hand-over, not by a
  bar pattern on glass; with it gone the panes ahead have the deck's
  column to themselves.
- **V's first-run door is 82 px narrower** than the trace column so the
  two panes ahead fit without overlap (designer, this round). The
  two-step sign-in doors keep the exact column.

## Open for the owner

- **Which direction.** Recommendation: **W, the brink**. It is the
  smallest addition to S and the most exact: the one element the door
  and the dashboard share is already standing in the room, and the
  hand-over is a measurement, not a reveal. V is the most literal fit to
  the grid and the strongest still frame; its cost is that the door is
  wide and the gutter panes are thin. X is the most atmospheric and the
  weakest on the owner's "not generic" test: blurred shapes behind
  glass are a known look, and the tie to birdcage is in the geometry
  rather than in anything the visitor can name.
- **W's axis under the door.** The quarter-hour axis (ticks and
  `15 M`) is the band's own scale, shown before sign-in. It reveals no
  data; it does tell a stranger what kind of page is behind the door.
  Recommendation: keep it; the alternative is the brink alone, which
  reads as a stray line.

## Owner verdicts

(none yet)
