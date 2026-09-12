# Design round 2 — dashboard shell (#3)

Opened by the round-1 verdict (owner, 2026-09-12, verbatim): **"You've
really failed to bring across the visual identity and style of mikroview.
Horrible side bar, lack of proper use of colour. Generic tables, cards,
forms."**

Round 2 is built from mikroview's ratified surfaces, not its tokens:
`mikroview/docs/design/concepts/round-30/the-whole.html` (the fall, the
stream, the docket). What that means here:

- No sidebar, no top bar, no cards, no boxed tables, no page heading.
  Wordmark floats top-left (`BIRD` ink, `CAGE` accent); live status,
  flag count and time chips float top-right; the deck is sideways names
  on the right edge (THE WIRE · HITS · VISITORS · CANARIES · AUDIT LOG ·
  SETTINGS).
- **The wire** is birdcage's fall: canaries as columns, an amber brink
  labelled `NOW · hh:mm:ss`, time falling below it with a mono gutter,
  density curves per port above the brink, a dim heartbeat tick a minute
  per canary, a dashed flag line where the sweep was born.
- **Hits** is the stream: `◂ bar` handle, filter box with `term ⌫`
  chips, whisper sparkline with a stats sentence, flat hairline table,
  flagged rows tinted with ⚑, footer sentences.
- **Visitors** is the docket: tabs under the wordmark, outlined amber
  `clear all`, dashed-underline inline filters, a colour stripe and bold
  label per row, a drawer with prose story · raw OpenCanary lines · the
  episode ticks · pill actions.

Colour carries meaning, never decoration: lane colours name the canary
(lan/srv/iot/guest), visitor kinds get their own stripe colours (sweep
`#ff5470`, repeat `#ff9e64`, from inside `#f072c8`, one touch
`#b8c56a` — mikroview's flag-kind palette, reassigned), amber is only
ever "now", alarm is only ever a flag.

## Directions

| Letter | Name | Landing | Idea |
|-------:|------|---------|------|
| D | **The wire** | the fall | Time-and-canaries hero first. The sweep reads as a diagonal thread across the wires. Hits and Visitors are the stream and the docket. |
| E | **The docket** | visitors | Who-is-here first, one row per visitor with a sentence of evidence. The wire rides above as a slim ribbon (one line per canary, brink on the right) and folds away when a visitor opens. |

## Scenes (both directions prove all three)

1. landing — `d-wire` / `e-docket`
2. hits filtered to `source: 203.0.113.42 ⌫` — `d-hits` / `e-hits`
3. the sweep visitor opened in the docket — `d-visitor` / `e-visitor`
   (E's drawer also lists the visitor's hits)

## Data story (unchanged from round 1)

See `../round-1/README.md` §Data story. Now is 22:04:31 on 2026-09-12;
the 15-minute wire runs 21:49:31 → now.

## Palette

Lane palette unchanged (validated in round 1). Visitor-kind stripes are
labels with a bold text marker, never series colours, so they are outside
the validator's remit.

## Capture

`node capture.mjs` → `shots/<scene>.png`, 1600×1000 @2x. Every shot
inspected. Fixes this round: dead band between chips and band heads
(wire regenerated at 38 px/min); ribbon NOW label clipped; legend line
colliding with the guest wire; docket stripe leaking into the drawer's
inner hits table (selector scoped to `tr > td:first-child`).

## Verdicts

_(pending)_
