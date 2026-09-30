# ADR-0004: The dashboard shell is "the trace"

**Status:** Accepted
**Date:** 2026-09-12

## Context

#3 (dashboard shell) needed a ratified visual direction before the Svelte
build. Six visioning rounds under `docs/design/concepts/round-1..6/`
(2026-09-12) went from three concepts to one shell, with the owner's
verdicts recorded verbatim in each round's README. The steer that shaped
it: the successful result is zero activity on every canary, so the quiet
page is designed first and the sweep night has to fit inside it.

## Decision

The shell is round 6, direction M — **the trace, outlined · silence in
ink** (`docs/design/concepts/round-6/direction-m-trace-outlined-ink.html`).
Its rules:

1. **The band.** Four heartbeat lines, one per canary, 12 px apart, the
   full width of the page, under a sentence that says what matters now.
   One time axis: the last quarter hour stretched, the day compressed,
   the fortnight squeezed; the right edge is "now". A line is a canary's
   heartbeat: unbroken means it is phoning home.
2. **A rise is a visitor.** Each hit is a smooth bump above its canary's
   line, coloured by kind (sweep, repeat, from inside, one touch), with
   its words at the top: what was tried, then `who → canary · when`. A
   visitor with many hits gets one labelled rise and low unlabelled
   ripples. Labels never cross a bump or another label; in the last
   300 px they hang left.
3. **A drop is silence.** A silent canary's line curves below the band
   and runs on as dashed grey, with a hollow marker at the last heartbeat
   and a sentence. Silence is a fault, not a visitor: ink, never alarm
   colour.
4. **Tiles beneath the band**, one per canary: name, status sentence,
   listening ports, hits in range, actions when there are any. The tile
   is a box whose 1 px outline is the canary's colour. A silent canary's
   box becomes a dashed grey outline with no fill — the same mark as its
   dropped line.
5. **Events beneath the tiles**: one row per visitor (time, kind,
   sentence, pill actions), newest first; on a quiet day one line of
   prose.
6. **Identity** follows mikroview: free chrome on the void, wordmark,
   range chips top right, sideways deck on the right edge, sentences as
   interface, colour as meaning (lane colours identify canaries, kind
   colours identify visitors, green means ok, amber only ever means
   "now"), mono for data and sans for prose.

Palette: lane and kind colours validated in round 1
(`round-1/README.md`); no new colour since.

## Consequences

- The Svelte build (#3 step 3) implements this shell; the generator
  `round-6/gen.py` is the reference for geometry, label placement and
  copy, not code to port.
- The three scenes (quiet fortnight, canary gone silent, sweep night) are
  the acceptance cases for the build: each must render as its concept
  shot does.
- New surfaces (visitors, audit log, settings) get their own visioning
  rounds and extend this ADR or add one; they do not restyle the shell.

## Extension: the canary page (round 7, #115)

Owner, 2026-09-23: **"22 O"** — the line, alone · ledger
(`round-7/direction-o-line-alone-ledger.html`). N (prose) dropped.

One canary's own page keeps the shell and adds:

1. **The line, alone**: this canary's band line at its own scale (rises
   up to 60 px), with the fortnight's earlier silences marked on it as
   the same hollow ink circle the band uses.
2. **Self-test marks**, both ink, no new colour: a hollow tick *under*
   the line is birdcage testing its own canary (04:00 daily), placed
   under the line so it is never read as a visitor; a filled tick with
   words *above* the line is a run that failed.
3. **Self-test as a ledger**: one outlined card per service, outlined
   in the grade's colour (`--ok` answered, `--ink` did not answer,
   dashed `--ink-3` untested); the grade word (marked, challenge-marked,
   attributed) under the answer. Untested is not a fault.
4. **History as a thread**: every state the canary has been in, newest
   first, one line each, with the band's own dots down the left.
5. **Facts** in a column to the right; actions as pills under them, only
   the ones the state earns (run the self-test now, lookback in
   mikroview, mark as maintenance).

Acceptance cases for the build are the four round-7 scenes: quiet and
answers when tested; deaf on telnet; silent, third time this week; the
sweep night from this canary.

## Superseded

Rounds 1–5 directions A–L, each dropped by a recorded verdict: see the
round READMEs. Nothing in them is lost — the night book's gaps-as-words,
the score's words-beside-the-mark and the pulse's full-width lines all
survive in the trace. Round 7 direction N (the canary page as prose)
dropped 2026-09-23 for O.
