# Design round 5 — dashboard shell (#3)

Opened by the round-4 verdict (owner, 2026-09-12, verbatim): **"I think it
would be better if we ran the four lines very close together, and blips
raise up above, with nice curves and a label. That way, they can takethe
full width of the screen. but only a small vertical, which is right for
something that's quiet most of the time."** and, in the same reply:
**"Beneath it, we can have the canary tiles/cards, and beneath that the
events."**

Round 5 is that layout. It carries the pulse's full-width heartbeat lines
(round 4, I) and the score's words-beside-the-mark (rounds 3–4) into one
shape:

- **The band.** Four heartbeat lines 12 px apart, the full width, under
  the sentence. A line is a canary's heartbeat: unbroken means it is
  phoning home. Dim marks on the stretched quarter hour are single
  heartbeats.
- **A rise is a visitor.** Each hit becomes a smooth bump above its
  canary's line, coloured by kind, with its words at the top: line 1 the
  credentials or path tried, line 2 `who → canary · when`. A visitor with
  many hits (the repeat knocker) gets one labelled rise on its widest
  cluster and low unlabelled ripples for the rest.
- **A drop is silence.** A silent canary's line curves down below the
  band and runs on dashed in ink, with a hollow marker at the last
  heartbeat and a sentence. No alarm colour: it is a fault, not a visitor.
- **Beneath the band, the tiles.** One per canary: name, status sentence,
  the ports it listens on, hits in the range. The silent tile carries its
  actions.
- **Beneath the tiles, the events.** The round-3 rows (time, kind,
  sentence, actions); on a quiet day one line of prose.

Label placement: a labelled rise starts 34 px high; its words try the
top, then hanging left, then hanging right of the rise; if all three
collide with an earlier label or bump it climbs 30 px and tries again.
Labels in the brink zone (the last 300 px) hang left so nothing runs off
the edge. The brink line stops just above the highest label.

## Directions

| Letter | Name | Twist |
|-------:|------|-------|
| J | **The trace** | Tiles as cards: raised surface, hairline border, canary colour as a 3 px bar down the left edge. |
| K | **The trace, unboxed** | Same tiles with no box: text on the void, one rule in the canary's colour along the top. |

Everything above the tiles and below them is identical between J and K.

## Scenes (both directions prove all three)

1. a quiet fortnight — `j-quiet` / `k-quiet` (Sat 5 Sep, 23 quiet days)
2. a canary gone silent — `j-silent` / `k-silent` (canary-iot last heard
   21:58:19, silent 6 m 12 s)
3. the sweep night — `j-night` / `k-night` (Fri 12 Sep)

Each direction is one URL; the scenes are sections down the page.

## Data story

Unchanged from round 4 (`../round-4/README.md` §Data story). Additions:

- Ports per canary: lan ssh 22 · http 80 · smb 445; srv ssh 22 · mysql
  3306 · ftp 21; iot telnet 23 · ssh 22 · smb 445; guest telnet 23 ·
  ssh 22 · http 80.
- Tile hit counts, 14 d, sweep night: lan 4, srv 3, iot 222, guest 2.

## Palette

Lane and kind colours unchanged from round 3 (validated round 1). Rise
fills are the kind colour at 14 % over the void; no new colour.

## Capture

`python3 gen.py` writes both HTML files in full; `node capture.mjs` →
`shots/<scene>.png`, 1600×1000 @2x. Every shot inspected. Fixes this
round: sweep labels piled up at the brink and crossed each other's
bumps (labels now hang left in the brink zone, and only the widest
cluster of a visitor is labelled); the touch label crossed the repeat
ripples (bumps and labels are both obstacles); the inside label climbed
into the paragraph (try top / left / right before climbing); tile status
text ran under the hit count; the silent tile's status wrapped and
crowded the events heading (shortened, events moved down 36 px in that
scene); the brink line ran the full height on quiet days.

## Verdicts

Pending.
