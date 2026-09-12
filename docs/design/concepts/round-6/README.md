# Design round 6 — dashboard shell (#3)

Opened by the round-5 verdict (owner, 2026-09-12, verbatim): **"I like
the boxed. But I'd prefer the outline of each box was the colour
signal."**

Round 6 is round 5's J (the trace, boxed tiles) with that one change:
the 3 px colour bar down the tile's left edge is gone, and the box's
1 px outline is drawn in the canary's colour. Everything else — the
band, the rises, the drop, the events, the data story — is carried
forward verbatim from `../round-5/`.

## Directions

| Letter | Name | Twist |
|-------:|------|-------|
| L | **The trace, outlined** | The ask exactly: every tile outlined in its canary's colour in every state. A silent canary keeps its colour on the box; its words and dot go to ink. |
| M | **The trace, outlined · silence in ink** | Same, plus: a silent canary's box becomes a dashed grey outline with no fill, the same mark its dropped-out line makes in the band. Only the silent scene differs from L. |

M is an addition the owner did not ask for, offered because the band
already says "silence = dashed ink" and the tile can say it the same
way. It stands or falls on its own.

## Scenes (both directions prove all three)

1. a quiet fortnight — `l-quiet` / `m-quiet`
2. a canary gone silent — `l-silent` / `m-silent`
3. the sweep night — `l-night` / `m-night`

## Data story and palette

Unchanged from round 5. No new colour: the outline is the lane colour
at full strength, and the silent outline in M is `--ink-3`.

## Capture

`python3 gen.py`; `node capture.mjs` → `shots/<scene>.png`. All six
shots inspected. Fix this round: the lan and srv tile statuses on the
sweep night ran to two lines and broke mid-phrase ("from inside /
19:11"); they now break deliberately before the second visitor.

## Verdicts

Owner, 2026-09-12, verbatim: **"Let it go gray. Good idea."**

M (the trace, outlined · silence in ink) is the ratified dashboard
shell; L dropped. Recorded as `../../../adr/0004-dashboard-shell.md`.
The visioning rounds for #3 end here; the build follows the ratified
direction.
