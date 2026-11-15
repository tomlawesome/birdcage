# Design round 13 — sign-in: mikroview's door, and one alternative (#8, slice B)

2026-11-15. Round 12's verdict: "Just reuse Mikroviews setup I guess.
Give it a slight birdcage twist. You can have one more go at an
alternative."

## The directions

| | Name | What it is |
|---|---|---|
| AE | Mikroview's door | Mikroview's sign-in screen (`AuthScreen.svelte`, `Fullfall.svelte`) carried over: centred stack, wordmark in the amber box, underlined centred fields, outlined "Enter" pill, SSO below a divider, the same one-beat entrance. The change: the strokes run left to right, in the four network colours, where mikroview's fall top to bottom. |
| AF | Bars | The same stack and wording between cage bars. Thin bars fill the window either side of a centre gap; the two bars at the gap are amber and replace the amber box. A glint crosses the bars every 11 seconds. On entering, the two halves slide apart. |

Both are plain HTML and CSS: no canvas, no WebGL. Each has four states:
sign in, refused, code, and the dashboard after entering.

## Carried from mikroview unchanged

Wording ("account", "password", "Enter", "Sign in with SSO", "Enter your
code", "Your password was right. Enter the current code from your
authenticator app to finish signing in.", "Use your passkey instead",
"Use a recovery code instead"), sizes, spacing and the entrance timing.

## Changed for birdcage

- Colours are birdcage's shell tokens (ADR-0004).
- The refusal message is ink, not red: on birdcage red means an alarm.
- The main button is mikroview's outlined pill. This replaces answer 4a
  (filled main button), which was given for the earlier designs.

## Not drawn yet

First run, enrolment, recovery codes, session expired and lock-out
follow mikroview's own screens for those steps once a direction is
chosen. The prototypes show a picture of the dashboard after entering; a
real build loads nothing from the dashboard before sign-in.

## Files

`door.css` and `door.js` are shared by both pages. `node shot.mjs`
retakes `shots/` from the design host.

## Open for the owner

Which of the two is built (question 20).

## Owner verdicts

2026-11-15, answering question 20: "20b bars is actually quite good, I
like it, but lets develop it further, bring in more colour to the glint
in keeping with the app. We could maybe play with some of the bars
showing signal signs, too. But don't over do it."

AF (Bars) goes forward and is developed in round 14. AE is dropped.
