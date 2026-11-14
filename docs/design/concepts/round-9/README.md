# Design round 9 — the doors, developed (#8, slice B)

2026-11-14. Round 8's verdict: "The doors looks interesting, not a fan of
the other ideas. But it needs development, so that it's jaw dropping,
awesome, visually sumptuous, rich in character, high fidelity, stunning."
This round keeps R's idea — each step of the gauntlet is a door; the
doors you have passed fold to spines on the left, the doors ahead wait on
the right, the cage is always the last — and develops it three ways.
Each direction is a different answer to "what are the doors made of and
how do they move", not a palette swap: S is glass and light, T is card
and ink on a desk, U is the cage's own wire.

## The problem

Unchanged from round 8: one or a few admins sign in to a dashboard whose
good state is nothing happening. The door carries the whole gauntlet —
password, second factor, first run with the setup code from the server
log, authenticator enrolment with recovery codes shown once, a session
that timed out while the dashboard was open (#190), refusals and "too
many tries" — and shows nothing the cage has seen until the visitor is
through. Now it must also be a thing worth looking at.

## Shared by every direction

- The ratified base is carried verbatim: round 6/7 palette (`--void`,
  `--ink`, `--accent`, `--ok`, `--now`), mono for data, sans for prose,
  the wordmark and version in the chrome. No new colour: the richness is
  light, depth, material and type, not hue.
- **A refusal is ink, never alarm.** As round 8 decided: red is the
  trace's word for visitors; a wrong password turns the door to ink and
  a closed door is dashed, the way a silent canary is drawn.
- **Nothing the cage has seen is shown before sign-in.** The only data
  on the page is the visitor's own address and birdcage's version.
- **The limiter** is the gauntlet design's: five refusals per name and
  per address in five minutes; passkey and SSO are not counted; `wren`
  can still sign in.
- **Session rules corrected.** Round 8's copy said sessions end "after a
  day idle"; the real rules (ADR-0016 §6, gauntlet v0.4.2) are: a session
  ends after one hour unused and after one day whatever happens. Within
  that day a timed-out session comes back with the password alone, or a
  passkey, with no second factor (owner, 2026-11-14, answer 5a); after
  the day it is a full sign-in with the second factor. The timed-out
  scene says exactly that: `ada` signed in at 07:31, last touched the
  dashboard at 07:52, an hour unused ended the session at 08:52, the
  dashboard behind the door is 26 minutes behind, and the full sign-in
  is due again by Sunday 07:31. The factor scene's footer says the two
  limits in one line.
- **R's filled primary button is shown again** in all three: the door's
  one button is filled in `--accent`, every other action an outlined
  pill or a bare link. Still open below.
- Timed out: the real dashboard stays behind the door, dimmed under a
  scrim, as in round 8; the point of the scene is that what is behind
  the door is stale.
- The QR square is a deterministic placeholder pattern; each page says so.

## Directions

| Letter | Name | Made of | How it moves |
|-------:|------|---------|--------------|
| S | **Smoked glass** | Dark frosted panes hung in a deep room, lit from one side. The current pane blurs what is behind it (`backdrop-filter`), has a bevelled edge and a grain of frost; passed panes are seen edge-on, swung back on their hinge, green-ticked; panes ahead wait in the depth; the cage is a lit pane with the bars showing through the frost. A refusal fogs the pane and inks its edge; a closed door is a pane dashed round and dimmed. | The passed pane swings away on its hinge (`rotateY`) and the next arrives out of the depth (`translateZ`); on the last step the cage's light fills the pane, then the room. |
| T | **Slate and ink** | Heavy slate cards on a desk, set in a serif (Charter, Palatino, Georgia) with a bold name in the hero line. The card you are on is squared in front; passed cards lie face down on a fanned pile at the left, title and tick at the corner; cards ahead sit under tabs at the right like a file. A refusal is a rectangular ink stamp across the card, grained with turbulence; a closed door is a card stamped shut with the countdown on it. | The passed card lifts and turns face down onto the pile; the next card comes forward from its tab; on the last step the cage card's light opens from its centre and fills the desk. |
| U | **Wire gates** | Arched gates of fine wire — the cage's own material — standing in a corridor. The current gate is a wide arch with its wires parted down the middle so you can read what is written in the gap; passed gates stand closed and narrow behind you in green wire with a fan of spokes; gates ahead stand small down the corridor; the cage is the last arch, lit. A refusal turns the wires to ink and hangs a tag from one; too many tries meshes the gate shut and draws it dashed. | The gate's wires part down the middle and you walk through; the next arch comes up the corridor to meet you (`scale` from small); on the last step the cage arch grows until its wires fill the room, and they part too. |

Each direction has a motion page (`motion-<letter>.html`) looping the
door-to-door transition and the final step into the cage, 12 s per
loop. Under `prefers-reduced-motion: reduce` the page is a still of
"door one passed, door two faces you" and the transitions are instant.

## Scenes (every direction proves all eight, same data)

1. sign in — password, "use a passkey", "sign in with SSO" — `<x>-signin`
2. second factor — six-digit code, "use a recovery code instead" — `<x>-factor`
3. first run — the setup code from the server log, the first admin — `<x>-firstrun`
4. enrol an authenticator — QR, manual key, confirm with a code — `<x>-enrol`
5. recovery codes, shown once — `<x>-codes`
6. timed out — dashboard behind, dimmed; password alone to carry on (#190) — `<x>-timeout`
7. refused — a wrong password, four tries left — `<x>-refused`
8. too many tries — five refusals, a 4 min 12 s wait, `wren` unaffected — `<x>-locked`

Scenes 4 and 5 are the brief's one enrolment scene split in two, as in
round 8, so the recovery codes get a page of their own.

## Data story

Round 8's, unchanged except the timed-out thread. Sat 14 Nov 2026,
birdcage 0.2.0. `ada` (admin) comes to the door at 09:18:04 from
192.0.2.10; password accepted 09:18:09; last signed in Thu 13 Nov 09:41.
First run: setup code `7KQW-93HD-2MXF`, valid until 09:27, printed once
in the server log; authenticator key `JBSW Y3DP EHPK 3PXP …`, account
`birdcage:ada`; ten recovery codes `k7mq-4d2x` … `g2tb-8nxv`. Timed out:
signed in 07:31, last touched 07:52, session ended 08:52, dashboard 26
minutes behind, full sign-in due Sunday 07:31. Refusals: 09:18:07 (four
left), then :19, :28, :39, :48 — closed to `ada` from 192.0.2.10 until
09:23:00. Documentation-range addresses only; no real names.

## What each effect costs to build (Svelte + CSS, no WebGL)

- **3D door motion** (S hinge, U approach, T lift): CSS `perspective`,
  `rotateY`, `translateZ`, `scale` with keyframes or transitions on a
  Svelte `{#key step}` block. Cheap; one afternoon. Needs a
  reduced-motion branch that swaps the transition for a cross-fade.
- **Frosted glass** (S): `backdrop-filter: blur()` over the dimmed
  dashboard and the room's light. Cheap in CSS, but it is the one effect
  with a paint cost: a blurred pane over an animating backdrop repaints
  every frame. Keep the room behind it static and it is fine. Firefox
  and Safari both support it.
- **Grain and stamp texture** (S frost, T stamp): an inline SVG
  `feTurbulence` as a data URI, applied as `mask-image`. No asset, a few
  lines; a couple of hours including tuning. `mask-image` needs the
  `-webkit-` prefix for Safari.
- **Wire gates** (U): `repeating-linear-gradient` for the wires,
  `repeating-conic-gradient` for the fan, `mask-image` with a radial
  gradient for the parted gap; all declarative, no SVG geometry. A day
  to get the proportions right across the eight scenes.
- **Fanned pile and tabs** (T): absolutely positioned cards with
  `rotate()`; the stack order is a list. Half a day.
- **Serif type** (T): a system serif stack (Charter, Palatino, Georgia);
  no web font download, so it renders differently per OS. If T is
  chosen, one decision is whether to ship a serif (a licence and ~100 KB)
  or accept the system one.
- **`:has()`** is used only in the mock-ups' layout shorthand; the build
  would pass the state down as a prop instead. Nothing here needs
  JavaScript beyond the step state Svelte already holds.
- **Light fills** (the cage frame): a scaled element with a radial
  gradient and opacity keyframes. Cheap.

## Capture

`python3 gen.py`; `node capture.mjs` → `shots/<letter>-<scene>.jpg`,
`shots/<letter>-motion.jpg` (door two landed, 4.9 s), `-motion-cage.jpg`
(the cage filling, 10.2 s) and `-motion-still.jpg` (reduced motion).
1440×900 at device scale 2, 33 shots, all inspected, four passes.
Shots are JPEG at quality 90 rather than PNG: the grain made the PNGs
63 MB for the round, the JPEGs are 9.5 MB and indistinguishable at a
side-by-side crop. The capture script freezes the caret.

Fixed between passes: S's wide doors (enrol, codes) pushed the passed and
cage panes off both edges (wide door narrowed, side panes slimmed); S's
light beam had hard polygon edges (blurred); S's and U's cage never grew
in the motion loop (a breathing animation outranked the fill — selector
specificity); T's ahead tabs were hidden behind the current card (ahead
cards now share the top edge and grow outward); T's pile hid every card
but the first (fanned, title and tick at each corner); T's stamp was an
oval of grit (rectangular, softer grain); T's cage frame was a whiteout
with unreadable text (a soft accent pool, text in ink); U's buttons
wrapped into tall ovals (no-wrap pills); U's confirm button overflowed
the arch; U's perch rings sat wrong on fields without a note (rings moved
onto the field box); U's tick overlapped the fan on passed gates; the
motion caption was struck through by U's wires in the cage frame (caption
on a void pill, the cage bars thin out behind the sentence, the passed
door fades as the cage fills in all three); T's hall sat high and left
the bottom of the screen empty (lowered).

## Open for the owner

Only choices that could genuinely go either way; everything else is
decided above.

- **R's filled primary button**, carried from round 8: the shell has only
  outlined pills; all three directions fill the door's one button in
  `--accent`. Recommendation: keep it on the door only; a door needs a
  handle, and the shell's pills stay as they are.
- **T's serif.** The shell is sans throughout; T sets the door in a
  serif for weight and character, and the cage after it is sans.
  Recommendation: if T is chosen, keep the serif on the door only, with
  the system stack (no web font); the change of voice at the threshold
  is the point.
- **U's centred composition.** The shell's sentences are left-aligned; U
  centres the door's text inside the arch because an arch reads from its
  keystone. Recommendation: accept it for U; S and T stay left-aligned
  like the shell.
- **The dimmed dashboard behind the timed-out door** (all three, as in
  round 8): the stale page is there, unreadable under the scrim, to say
  "26 minutes behind". The alternative is a plain void. Recommendation:
  keep the dimmed page; the visitor signed in on this device within the
  day, and nothing in it is legible.

Skipping the second factor after an idle timeout, open in round 8, is
no longer open: the owner ratified it on 2026-11-14 (answer 5a).

## Owner verdicts

(none yet)
