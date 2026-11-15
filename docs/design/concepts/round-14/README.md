# Design round 14 — sign-in: bars, developed (#8, slice B)

2026-11-15. Round 13's verdict on Bars: "20b bars is actually quite good,
I like it, but lets develop it further, bring in more colour to the glint
in keeping with the app. We could maybe play with some of the bars
showing signal signs, too. But don't over do it."

Layout, form, wording and the entrance are round 13's AF, unchanged.

## What changed

- **Glint.** The band that crosses the bars was amber only. It now
  carries the four network colours in order (lan, srv, iot, guest), so
  each bar turns through them as it passes. One pass every 13 seconds,
  left to right across both halves as one movement.
- **Signals.** Four bars, one per network colour, show a signal in turn,
  about one every three seconds. Every other bar stays still.

| | Name | Signal |
|---|---|---|
| AG | Bars, pulses | A short pulse of light climbs the bar. |
| AH | Bars, lit | The whole bar lights in its colour, flickers once and fades. |

## Limits kept

- The signals run on a fixed timer. They show nothing the cage has seen:
  no data is loaded before sign-in.
- Amber stays on the two bars at the gap only, apart from its place in
  the glint.
- With reduced motion set, the glint holds still and the signals are
  hidden.
- Still plain HTML and CSS.

## Files

`door.css` and `door.js` are shared by both pages. `node shot.mjs`
retakes `shots/` with the animations frozen at chosen moments.

## Open for the owner

Which signal, or neither (question 21).

## Owner verdicts

2026-11-15, answering question 21: "I like the pulses but when a pulse
appears it should also make the line wiggle in a bounded but randomised
way, and there should be slightly more of them. The glint is alright but
it's just a generic sweep and a bit boring. I'd be willing to look at
some other version that's similar but different maybe."

AG (pulses) goes forward with those changes; AH (lit) is dropped. The
sweep is replaced: round 15 draws alternatives.
