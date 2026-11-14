# Design round 8 — sign-in through gauntlet (#8, slice B)

2026-11-14. The way in to the ratified shell (ADR-0004, round 6 M) and
the canary page (round 7 O). Three completely new ideas, as asked: not
mikroview's sign-in screens, and not a palette swap of each other. Each
differs in spatial metaphor, voice and texture, and each says how it is
the door to the trace.

## The problem

One or a few admins sign in to a dashboard whose successful state is
nothing happening. The door has to carry the whole gauntlet — password,
second factor, first run with the setup code from the server log,
authenticator enrolment with recovery codes shown once, a session that
idled out while the dashboard was open (#190), and refusals including
"too many tries" — without showing anything the cage has seen until the
visitor is through.

## Shared by every direction

- Palette, type and marks are round 6/7's, copied so the round stands
  alone: void, ink, mono for data, sans for prose, no new colour.
- **A refusal is ink, never alarm.** The trace keeps red for visitors;
  a wrong password is a fault, drawn the way the trace draws silence
  (ink, or dashed grey when the door is closed). Decided here, not
  asked: alarm red on the sign-in page would make the shell's one rule
  for red mean two things.
- Nothing the cage has seen is shown before sign-in; the only data on
  the page is the visitor's own address and birdcage's version.
- The limiter is the gauntlet design's: five refusals per name and per
  address in five minutes; a passkey or SSO sign-in is not counted; the
  wait is for that pair only, so `wren` can still sign in.
- Timed out: the real dashboard stays behind, dimmed under a scrim, and
  the password alone carries on; the second factor is not asked again
  on the same device.
- The QR square is a deterministic placeholder pattern (no QR library
  is installed and a mock-up does not need one); each page says so
  under the square.

## Directions

| Letter | Name | The idea |
|-------:|------|----------|
| P | **On the line** | The form is drawn with the shell's own marks. Each field is a band line the width of the page, with the visitor's words above it as a rise's words sit above a heartbeat; "now" is the amber brink at the right, and the sign-in button sits against it. A refusal is the line dropping under the band and running on dashed — the silence mark. Timed out: one band is cut through the dimmed dashboard and the password line sits in it. Way in to the trace: it *is* the trace's geometry, one line per thing to type. |
| Q | **The log** | The door is a server-log transcript in mono: time in a gutter, one line appended per step, a bracketed field where a line waits for you. On first run the setup-code line is the very line the admin just read in their terminal. Refusals append in ink; too many tries append five lines and a countdown. Timed out: the log rises as a drawer from the foot of the dimmed dashboard. Way in to the trace: the audit log's voice and the shell's mono data, with the sideways deck showing "the door" before "the trace". |
| R | **The doors** | The gauntlet made visible as a corridor. The current step is one wide door with the shell's hero sentence; doors already passed fold to sideways spines on the left (ticked, in `--ok`), doors ahead wait as dashed spines on the right, the last always "the cage". First run is four doors; sign-in is two. A refused door's outline turns to ink; a closed door is dashed, like a silent canary's tile. Timed out: one door slides in from the right over the dimmed dashboard. Way in to the trace: the shell's sentences and its sideways deck, as the steps themselves. |

## Scenes (every direction proves all eight, same data)

1. sign in — password, "use a passkey", "sign in with SSO" — `<x>-signin`
2. second factor — six-digit code, "use a recovery code instead" — `<x>-factor`
3. first run — the setup code from the server log, the first admin — `<x>-firstrun`
4. enrol an authenticator — QR, manual key, confirm with a code — `<x>-enrol`
5. recovery codes, shown once — `<x>-codes`
6. timed out — dashboard behind, dimmed; password to carry on (#190) — `<x>-timeout`
7. refused — a wrong password, four tries left — `<x>-refused`
8. too many tries — five refusals, a 4 min 12 s wait, `wren` unaffected — `<x>-locked`

Scenes 4 and 5 are the brief's one enrolment scene split in two so the
recovery codes get a page of their own; they are shown once and deserve
the room.

## Data story

Sat 14 Nov 2026. birdcage 0.2.0 started at 09:12:04 with four canaries
enrolled and two accounts, `ada` (admin) and `wren`. `ada` comes to the
door at 09:18:04 from 192.0.2.10; her password is accepted at 09:18:09;
she last signed in Thu 13 Nov 09:41. First-run scenes replay the same
morning with no accounts: setup code `7KQW-93HD-2MXF`, valid until
09:27, printed once in the server log; authenticator key
`JBSW Y3DP EHPK 3PXP JBSW Y3DP EHPK 3PXP`, account `birdcage:ada`, ten
recovery codes `k7mq-4d2x` … `g2tb-8nxv`. The timed-out dashboard
stopped at 08:52:10, quiet, fourteen days without a visitor. Refusals:
09:18:07 (four left), then 09:18:19, :28, :39, :48 — closed to `ada`
from 192.0.2.10 until 09:23:00. Documentation-range addresses only; no
real names.

## Open for the owner

Only choices that could genuinely go either way; everything else is
decided above.

- **Where the refusal sits in P**: the dropped line (as drawn), or a
  sentence under the hero like Q and R. Recommendation: keep the drop;
  it is the one place the metaphor earns its keep.
- **R's filled primary button**: the shell has only outlined pills; R
  fills the door's one button in `--accent`. Recommendation: keep it in
  R only — a door needs a handle — and leave the shell's pills alone.
- **Second factor on the timed-out screen**: all three skip it on the
  same device, as mikroview does. Recommendation: keep; asking again
  for an idle timeout trains people to resent the factor.

## Capture

`python3 gen.py`; `node capture.mjs` → `shots/<letter>-<scene>.png`,
1440×900 at device scale 2. 24 shots, all inspected, three passes.
Fixed: P's timed-out strip had its actions and brink at the top (inline
offsets overrode the strip's); P's countdown class collided with the
closed-row class and collapsed both rows; empty fields drew their caret
at the far end of an invisible input (all three directions); P's
right-hand notes ran into the brink; the brink's time did not follow the
scene; Q's text-block QR stretched in the fallback mono font (now the
same SVG square as P and R); Q marked the wrong line as newest; R's doors
were taller than their content, R's passed spine was transparent over
the dimmed dashboard, and R's refusal note wrapped. The capture script
freezes the caret so a blink is never caught hidden.

## Verdicts
