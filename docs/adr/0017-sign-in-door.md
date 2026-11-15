# ADR-0017: The sign-in door is mikroview's, between cage bars

**Status:** Accepted (owner verdicts 2026-11-15 on #8: 24a, 25a, 26a)
**Date:** 2026-11-15
**Relates to:** #8 (sign-in), ADR-0016 (sign-in through gauntlet; its
decision 11 reuses mikroview's screens), ADR-0004 (the dashboard shell and
its palette), #189 (screens still waiting on mikroview).

## Context

ADR-0016 settled how sign-in works and that its screens are mikroview's.
It left what birdcage's door looks like. Eleven design rounds
(`docs/design/concepts/round-8` to `round-18`) tried corridors, glass and
live scenes; the owner set them aside for mikroview's own door with "a
slight birdcage twist", and chose the bars.

## Decision

The mock-up to build from is
`docs/design/concepts/round-18/direction-an-bars-all-screens.html` with
its `door.css`, `door.js` and `bars.js`. Build ports those files.

1. **The door.** Mikroview's sign-in: a centred column, the wordmark, two
   underlined fields, an outlined pill button `Enter`, then `or` and
   `Sign in with SSO` when SSO is configured. Mikroview's wording is used
   throughout, shortened. A refusal is ink text, never red, and never
   names another account.
2. **The bars.** Thin vertical bars fill the screen either side of the
   form. The two nearest the form are amber (`--now`) and take the place
   of mikroview's amber box round the wordmark. On entering, the two
   halves slide apart and the dashboard shows between them.
3. **Signals.** Coloured pulses climb random bars at uneven intervals, in
   the four lane colours. Behind a pulse the bar shows a sharp, irregular
   trace, like activity on the dashboard's lines; long spikes cross the
   neighbouring bars, and the two bars either side pick up a fainter trace
   of their own. Nothing crosses the amber bars into the form. Each bar
   also carries a faint drifting patch of colour (the shimmer).
4. **Caught signals.** About one pulse in four stops part-way up: the bar
   is cut there, beats red, and mends within about three seconds.
5. **A new colour.** The cut uses red, `--caught: #ec4850`. This amends
   ADR-0004's "no new colour since": red means a signal birdcage stopped,
   on the door only. It is not an error colour and is not used for text.
6. **Nothing the cage has seen is shown before sign-in.** Every signal on
   the door is drawn from a timer, not from data.
7. **Screens**, all on the same door: sign in; refused; too many
   attempts; second-factor code (passkey and recovery code as
   alternatives); first run, with the setup code from the server log; add
   a second step (choose, prove it, keep the codes); session expired, over
   the dimmed dashboard.
8. **Reduced motion.** The bars are drawn still; no pulses, no slide.

## Consequences

- The bars are a canvas, so their look is held by the pixel gate on still
  frames (`?t=N` in the mock-up draws a fixed moment), not by markup.
- Screens mikroview has not built stay on #189.

## Superseded

- Rounds 8 to 12 (the log, the doors, smoked glass, reeded glass, ribbons,
  the dome) and mikroview's door unchanged (AE): each round's README holds
  the owner's verdict.
- Round 14's sweep glint, round 15's passing light and ripple, and its
  smooth wiggle ("looks like something biological").
- The filled main button of answer 4a: replaced by mikroview's outlined
  pill when the owner chose mikroview's door.
