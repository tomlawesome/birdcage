# Design round 4 — dashboard shell (#3)

Opened by the round-3 verdict (owner, 2026-09-12, verbatim): **"I saw
both. I prefer the score. But it needs more work - we should bear in mind
that the successful result here is ZERO activity on every canary."**

Round 4 keeps the score (round 3, G) and re-centres it on the quiet
state. The principle behind both directions:

- An empty score is the product working, so the quiet page is the one
  designed first and the sweep night has to fit inside it.
- The canaries are the permanent subject. Each canary's line **is** its
  heartbeat: unbroken means it is phoning home; a break is silence.
- A silent canary is the other alarm. It is a fault, not a visitor, so it
  is drawn in ink, not alarm colour: hollow status dot, hollow marker at
  the last heartbeat, a dashed grey run to the brink, and a sentence.
- Visitors are ticks on the canary they touched, coloured by kind. They
  get rows, staves or chips only when there is one to write about.
- Kept from the night book (F): gaps written as words ("Quiet for 23
  days.", "No visitor in the window.").

## Directions

| Letter | Name | Twist |
|-------:|------|-------|
| H | **The quiet score** | Round 3's shape kept — sentence left, stave right, one compressed axis — with the canaries moved to the top permanently. Visitors become a section beneath: on a quiet day one line of italic prose, on the sweep night the round-3 rows with their own staves. |
| I | **The pulse** | Four heartbeat lines, full width, sentence above. No visitor rows: a visitor is a tick on the canary's line with its words beside the tick, plus a chip in the visitors line below. The quiet fortnight is four unbroken lines and a chip saying "none". |

## Scenes (both directions prove all three)

1. a quiet fortnight — `h-quiet` / `i-quiet` (Sat 5 Sep, 23 quiet days)
2. a canary gone silent — `h-silent` / `i-silent` (same day, canary-iot
   last heard 21:58:19, silent 6 m 12 s, "3 of 4 phoning home")
3. the sweep night — `h-night` / `i-night` (Fri 12 Sep, unchanged)

Each direction is one URL; the scenes are sections down the page.

## Data story

The sweep night is unchanged from rounds 1–3 (`../round-1/README.md`
§Data story, repeat visitor as refined in round 3). Additions:

- **Sat 5 Sep 2026, 22:04:31** — the quiet day. Last visitor Thu 13 Aug:
  one touch on canary-guest :23 from 198.51.100.200, cleared with a note.
  23 quiet days. Heartbeats every 60 s; newest 9/41/22/3 s ago.
- **Silent scene** — canary-iot's last heartbeat 21:58:19 (372 s ago);
  the other three unchanged. Status reads `3 of 4 phoning home ·
  canary-iot silent 6 m`.
- Range chips gain `90 d` — quiet stretches are the normal case, so the
  long view matters.

## Palette

Lane and kind colours unchanged from round 3 (validated round 1). New: the
silent state uses `--ink-2`/`--ink-3` only; no new colour. The ok green
carries the day count in the hero.

## Capture

`python3 gen.py` writes both HTML files in full; `node capture.mjs` →
`shots/<scene>.png`, 1600×1000 @2x. Every shot inspected. Fixes this
round: I's axis and staves sat under the hero and collided with its
text (moved down 156 px); I's action pills touched the axis labels in
the silent scene; the touch lyric collided with canary-srv's status line
(moved below the stave); the four visitor chips wrapped into the legend
(shortened); H's silent hero wrapped to an orphan word and left a gap
above the paragraph.

## Verdicts

Owner, 2026-09-12, verbatim: **"I think it would be better if we ran the
four lines very close together, and blips raise up above, with nice
curves and a label. That way, they can takethe full width of the screen.
but only a small vertical, which is right for something that's quiet
most of the time."** and, in the same reply: **"Beneath it, we can have
the canary tiles/cards, and beneath that the events."**

Neither H nor I goes forward as drawn. What carries into round 5: the
pulse's (I) full-width heartbeat lines, drawn as one tight band instead
of four spaced staves; the score's words beside the mark, now at the top
of a rise; the quiet-state principle from both (a flat trace is the
product working; a silent canary is drawn in ink). Round 5:
`../round-5/README.md`.
