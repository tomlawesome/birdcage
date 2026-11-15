# Design round 15 — sign-in: bars, pulses that wiggle, three kinds of light (#8, slice B)

2026-11-15. Round 14's verdict: "I like the pulses but when a pulse
appears it should also make the line wiggle in a bounded but randomised
way, and there should be slightly more of them. The glint is alright but
it's just a generic sweep and a bit boring. I'd be willing to look at
some other version that's similar but different maybe."

Layout, form, wording and the entrance are unchanged from round 13's AF.

## Pulses (the same on all three pages)

- A pulse starts every 1.0 to 1.8 seconds on a random bar that has none,
  in one of the four network colours. Round 14 had one every 3 seconds
  on four fixed bars.
- Behind the pulse the bar wiggles. The wiggle starts at the pulse's
  head, is strongest about 95 pixels behind it and dies away below. Its
  size (2.5 to 5.5 pixels), wavelengths and speeds are drawn at random
  for each pulse, and it is clamped to 6 pixels either way. The bar is
  straight again 1.4 seconds after the pulse leaves the top.
- The two amber bars at the gap never carry a pulse.

## What replaces the sweep

| | Name | Light |
|---|---|---|
| AI | Passing light | One soft light wanders behind the bars on an irregular path. Bars near it catch its colour, strongest at its height. The colour moves through the four network colours. |
| AJ | Ripple | No separate light. When a pulse passes 72% of the way down the window it sets off up to seven bars either side, which light in its colour one after another and fade with distance. |
| AK | Shimmer | Every bar has its own faint patch of one network colour, drifting up and down at its own pace. |

## Build notes

- The bars are now drawn on a 2D canvas (`bars.js`, about 90 lines):
  CSS cannot bend a line. No WebGL, no library.
- Everything runs on a seeded timer. Nothing is loaded from the cage
  before sign-in.
- With reduced motion set: straight bars, no pulses, the light held
  still.
- `?t=N` on a page draws it as it stands N seconds in; `shot.mjs` uses
  this to retake `shots/`.

## Open for the owner

Which light (question 22).

## Owner verdicts

2026-11-15: "The wiggle is ... very wrong, it looks like something
biological, which I won't say, and it's not at all how I envisaged it.
The wiggle I was referring to was sharper, more like network activity
from birdcage and mikroview."

The smooth, travelling wiggle is dropped. Round 16 redraws it as a sharp
activity trace.

2026-11-15, on question 22 (which light): "22c shimmer is good though,
other than the wiggle."

Shimmer (AK) is chosen. Passing light (AI) and ripple (AJ) are dropped.
