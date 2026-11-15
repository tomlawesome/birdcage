# Design round 11 — the glass, three positions (#8, slice B)

2026-11-15. Round 10's verdict: "Yeah I just feel like you've played it
safe with everything you've done so far." Rounds 8 to 10 each put a
rounded card on a dark page and decorated around it. This round removes
the card. In every direction the form is set as large type on the page
itself; fields are rules on the glass, not boxes; the one primary button
is the only filled shape. What differs between the directions is where
the visitor stands relative to the glass: in front of it (Y), behind a
closed door (Z), on it (AA). Each takes one real risk, named in the
table below.

Two earlier limits are dropped for this round: the glass is drawn by a
fragment shader (WebGL) rather than a blur filter, and the motion pages
move the whole scene, not one pane. The cost of each is stated below.

## The problem

Unchanged: one or a few admins sign in to a dashboard whose good state is
nothing happening. The door carries the whole gauntlet and shows nothing
the cage has seen until the visitor is through. It must be recognisably
birdcage and worth looking at, and not look like any other product's
sign-in page.

## Shared by every direction

- The ratified base is carried verbatim: palette roles (`--void`,
  `--ink`, `--ink-2`, `--ink-3`, `--accent`, `--ok`, `--now`, the four
  lane colours), mono for data and sans for prose, the wordmark and
  version in the chrome. Amber means "now" and nothing else.
- The shell's geometry is the door's geometry: the gutter at x = 54, the
  band from x = 190 to the brink at x = 1368 at y = 300, the tiles at
  y = 470. Every direction's last frame is the real quiet shell
  (`Quiet for 14 days.`), not a sketch of it.
- No card. The form is a column of type: an eyebrow line in mono (flow,
  step, date, time), a heading at 60 px, a sub-line, fields drawn as a
  label over a rule, the primary button filled in `--accent`, the
  alternatives as outlined pills or bare links.
- The steps are a rail at the top of the column: a green tick for each
  step passed, a filled dot for the current step, a dashed ring for each
  step ahead. The same rail in all three; what differs is how the glass
  shows the same steps.
- A refusal is ink, never alarm. A paused door is dashed.
- Nothing the cage has seen is shown before sign-in: the visitor's own
  address, the version and the time are the only data. No other account
  is named anywhere.
- Session rules as in rounds 9 and 10: one hour unused ends a session,
  one day ends it regardless; within the day a timed-out session resumes
  with the password alone or a passkey; the full sign-in with the second
  factor is due again by Sunday 07:31.
- The limiter is ADR-0016's: five refusals per name and per address in
  five minutes; passkey and SSO are not counted.
- The timed-out screen sits over the dimmed dashboard, as settled (owner,
  2026-11-15, 10a); the door's main button is filled, as settled (4a).
- The QR square is a deterministic placeholder pattern, not a real key.

## Directions

| Letter | Name | What is different | The risk |
| --- | --- | --- | --- |
| Y | through the glass | The visitor stands in front of a sheet of rolled glass that fills the viewport; the shader refracts a light behind it, so the sheet has a bright wavering edge rather than a blur. The form is on the near side, at the left, with a bevel in the gutter at x = 54. Each step passed is a sheet behind the visitor, seen as a thin green edge at the far left; each step ahead is a sheet in front, seen as a refracting edge towards the right. A refusal turns the sheet's edge to ink; a paused door's edge is dashed. The motion is a walk: the sheet in front scales up past the camera, and the next is already standing; the last sheet is the shell. | Composition and depth. Nothing frames the form; the page is mostly glass and one bright edge, and the eye has to be led by scale and position alone. The walk-through transition is a camera move, which no earlier round attempted. |
| Z | ajar | The page is a door, closed, near black. The only light on it is a slit at the brink, x = 1368, where the door stands open: 6 px at the first step, wider at each step passed, and the door's face takes the light from the slit. The form stands in the lit part of the face, right of centre. A refusal is the light gone: the slit closes and a grey hairline marks where it was. The paused door's hairline is dashed. At the last step the whole door swings away (`rotateY`) and the dashboard was behind it. In the timed-out scene the slit is wide enough that `NOW · 08:52:10`, the frozen dashboard's own brink label, is the one legible thing in the gap. | Light. Most of the page is black, the form is lit from one side only, and the whole mood rests on one line of light at the brink being enough. This is the direction that should make a reviewer nervous: it is austere to the point of risk, and it is also the one where the brink carries the most meaning. |
| AA | the floor | The visitor stands on a floor of black glass. The form, and standing slabs for the steps passed (green-edged, ticked) and ahead (dashed), are reflected below the horizon at y = 640; the reflection is a mirrored copy, darker and softer with distance, with a faint pool of light where the primary button stands. Timed out, the dimmed dashboard is both behind the form and in the floor. At the hand-over the horizon lifts to the band's height, y = 300, the slabs fall back, and the floor becomes the trace's dark ground. | Material. A reflective floor is the easiest of the three to do badly (every car advert), and the reflection doubles every element, so the page can crowd. The bet is that a nearly black mirror, with the reflections kept faint and the horizon exact, reads as a place rather than an effect. |

## Scenes (every direction proves all eight, same data)

1. **Sign in** — username and password; `Sign in`, `Use a passkey`,
   `Sign in with SSO`. One step ahead: `Authentication code`.
2. **Second factor** — `Enter your authentication code`; code half
   typed; `This code is valid for another 19 s.`; `Use a recovery code`;
   `Last sign-in: Thu 13 Nov, 09:41`. One step passed: `Password`.
3. **First run** — `Create the first administrator`, step 1 of 3; the
   server-log line with the setup code; setup code, username, password,
   confirm password; `Create administrator`, `Sign in with SSO instead`.
   Two steps ahead.
4. **Enrol an authenticator** — QR, key, `Code from the app`, `Confirm`;
   `The key is shown once.` One passed, one ahead.
5. **Recovery codes** — ten codes; `Continue`, `Copy`, `Download`,
   `Print`; `10 codes · none used`. Two passed, none ahead.
6. **Session expired** — over the dimmed dashboard frozen at 08:52:10:
   `Your session expired at 08:52 after an hour of inactivity. Enter
   your password to continue. A full sign-in, including your
   authentication code, is required again by Sunday 07:31.` Password;
   `A passkey can also be used.`; `Continue`, `Sign in as a different
   user`. One step passed, `Signed in 07:31`.
7. **Refused** — `Incorrect username or password. · 4 attempts left`;
   the heading in ink, the glass unlit.
8. **Too many attempts** — `Sign-in for this username from 192.0.2.10
   is paused after 5 failed attempts. Try again at 09:23.`; the countdown
   `4:12 until 09:23:00`; the fields dashed; `Passkey and SSO sign-in
   are not paused.`

The copy is round 10's, unchanged: conventional labels, the fact and the
next step, nothing else on the page.

## Data story

`ada`, an administrator, at the door from 192.0.2.10 on Sat 14 Nov,
birdcage 0.2.0. Scene times run 09:18:04 to 09:18:48. Last sign-in Thu
13 Nov 09:41. The dashboard behind the timed-out door is the quiet
14-day view, frozen at 08:52:10. No other account is named anywhere.

## What each effect costs to build, and what it falls back to

- **The glass shader** (all three): one fragment shader per direction on
  a full-viewport `<canvas>`, rendered at 1× (1440×900 texels, not
  device pixels) and upscaled by the browser; uniforms for time, mood
  (lit, ink, paused), the slit width or edge positions, and the horizon.
  Y refracts a light behind rolled glass (value noise, two octaves,
  offset sampling); Z lights a door face from a slit with a Lorentzian
  falloff and a bevel; AA draws a pool and a haze below the horizon.
  Each is under 60 lines of GLSL. Cost: two to three days to port into
  Svelte as one component with a `fx` prop, plus a day to tune on real
  hardware; the render loop is gated by `IntersectionObserver` and stops
  when the page is hidden. Fallback: when `getContext('webgl')` fails
  the canvas gets a `.nogl` class and the scene draws a CSS gradient
  with the same light direction; checked with WebGL disabled in Chromium, one scene per direction (not committed as shots).
  Reduced motion draws one frame with time fixed at zero.
- **Form as rules on glass** (all three): plain CSS; the focused rule is
  brighter and casts a soft glow. The mock-ups use `:has(.caret)` to
  mark the focused field; the build passes focus down as state. Cheap.
- **The rail** (all three): an `<ol>` with `aria-current="step"`. Cheap.
- **Y's walk-through**: two sheet layers animated with `scale` and
  `filter: blur()` on a 12 s loop; in the build, about 1.2 s on step
  change, on a `{#key step}` block. The shader's edge positions move
  with the sheets through the uniforms. One day.
- **Z's slit**: the slit width is a single number driven by step state;
  the shader draws the light, the DOM draws nothing for it. The swing is
  `rotateY(-104deg)` on the door layer with `perspective` on its
  parent, backface hidden. Half a day. Reduced motion: the slit jumps
  to the step's width; the swing is a cross-fade.
- **AA's reflections**: two mirrored DOM copies of the standing content
  (`transform: scaleY(-1)`, `aria-hidden` and `inert`), masked with a vertical
  gradient and blurred, near and far. The mirror doubles the DOM below
  the horizon; `inert` keeps it out of the tab order and the
  accessibility tree; the mock-ups also take the mirrored inputs out of the tab order. The horizon lift is a `top` transition on the
  floor and a `translateY` on the stand. One day. This is the one effect
  with a paint cost on every frame the content changes; the content
  only changes on step change, so it is fine.
- **Sideways labels** (AA's slabs, the shell's deck): `writing-mode:
  sideways-lr`; Safari needs `vertical-rl` plus `rotate(180deg)`.
- Nothing needs JavaScript beyond the step state Svelte already holds,
  except the shader component itself.

## Capture

`python3 gen.py`; `node capture.mjs` → `shots/<letter>-<scene>.jpg`,
`<letter>-motion.jpg` (step two landed, 4.9 s), `<letter>-motion-handover.jpg`
(the shell's first view, 10.2 s) and `<letter>-motion-still.jpg` (reduced
motion). 1440×900 at device scale 2, JPEG quality 90, 33 shots, all
inspected, six passes.

Fixed between passes: Y's refraction was far too strong (the edges ahead
looked like lightning and the window behind the glass like a moon;
offset reduced to a fifth, the window made a soft tall rectangle); Y's
timed-out scene hid the dashboard entirely (the shell is no longer
dimmed twice; the frost over it is lighter); AA's reflections were
invisible (the mask gradient was applied before the flip, so it masked
the visible half; the gradient now runs the other way); AA's horizon was
a hard two-tone split (the constant floor lift removed, the haze
softened); Z's light washed out the text on the lit face and spread
across most of the width (intensity and falloff reduced; the bloom
stays near the bevel); Z's version label and right-hand notes sat in the
slit's light (the version label moves under the wordmark, the notes
move under the actions, in Y as well, where the sheet ahead lit them);
Z's timed-out crack showed a cut fragment of the dashboard's time (the
slit is 104 px there, so `NOW · 08:52:10` is whole); every timed-out
scene drew a second version label over the shell's own chrome (removed);
AA's two slabs ahead in first run overlapped and the second was cropped
at the viewport edge (spaced 75 px apart, both inside the frame).

Fixed after the coordinator's review of the committed shots: Y's wordmark
and info button sat on the far-left bevel (the chrome starts at 78 px,
clear of it; the version label follows at 170 px; the motion page's
chrome too); Z's recovery codes 05 and 10 sat in the light (the slit is
84 px there, not 108, and the wide column runs 280–1140); Z's timed-out
paragraph ran into the bright gradient (the column starts at 620 and the
timed-out column is 500 wide, so the text ends by about 1105); AA's
passed slabs came within 10 px of the recovery-codes column (the wide
column starts at 190; 70 px clear); AA's first-run hints ran into the
next row's label (row gap 26 px, with the field and action margins
reduced to keep the form above the floor); the second-factor heading
wrapped with `code` alone on its second line in Y and AA (headings use
`text-wrap: balance`, which gives two even lines; Chromium 114+, Firefox
121+, Safari 17.5+; elsewhere the old wrap, which is legible, just
uneven).

## Decided

- **No card, in any direction** (designer, this round). The brief was to
  break the card-on-a-dark-page template; the form as large type with
  rules for fields is the common answer, and the directions differ in
  the glass, not the form.
- **The rail replaces the side panes** (designer, this round). Rounds 9
  and 10 drew each step passed and ahead as a pane with a label; here
  the rail at the top names them in text, and the glass shows them as
  edges (Y), light (Z) or slabs (AA) without text. Nothing on the page
  says what a thing is twice.
- **Z's timed-out slit is 104 px, wider than the step would give**
  (designer, this round), so that the frozen dashboard's `NOW ·
  08:52:10` is whole in the gap rather than a cut fragment. The brink
  label is the one thing worth seeing through the crack.
- **The version label moves out of the light in Y and Z** (designer,
  this round): it sits after the wordmark in Y and under it in Z. In AA
  it stays at the top right as in the shell.
- **Shaders at 1×** (designer, this round). Rendering the glass at
  device resolution quadruples the fragment work for a blur-soft image;
  at 1× it is indistinguishable in the shots and runs on integrated
  graphics.

## Open for the owner

- **Which direction.** Recommendation: **Z, ajar**. It is the furthest
  from a generic sign-in page and the most birdcage: the brink is the
  whole light source, and every state of the gauntlet is a state of that
  one line (open, wider, gone, dashed), which is exactly how the trace
  already speaks. Y is the strongest single frame and the best motion,
  and its risk is that the glass is decoration the visitor could ignore.
  AA is the most atmospheric and the one most likely to be read as an
  effect; its reflections are kept faint for that reason, and at that
  faintness the floor may not earn its cost.
- **Z's darkness.** Z's first-step page is near black with a 6 px slit;
  a visitor arriving cold sees a dark page with a form in it. The
  alternative is a wider first slit (about 24 px) so the door reads as a
  door at once. Recommendation: keep 6 px on the sign-in and first-run
  scenes; the first step should be the darkest and the widening is the
  point. If the owner finds the first frame too bleak, 24 px costs
  nothing.

## Owner verdicts

2026-11-15: "I strongly dislike all of them."

- Y, Z and AA: all dropped. Nothing from this round is carried forward.
- Round 9's S (smoked glass) remains the only direction the owner has
  called the best so far.
