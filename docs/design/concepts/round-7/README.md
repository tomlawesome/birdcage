# Design round 7 — the canary page (#115)

The first surface after the ratified shell (ADR-0004). One canary's own
view: its band line alone, at its own scale; a status sentence and the
actions it earns; the self-test, per service; every state the canary
has been in, newest first; and the facts.

The shell is not restyled: same band, rises, drops, tiles, events,
identity and legend as `../round-6/`. Two new marks, both in ink, no
new colour:

- a **hollow tick under the line** is birdcage testing its own canary
  (04:00 daily); it sits under the line so it is never read as a visitor;
- a **filled tick with words above the line** is a run that failed.

## Directions

| Letter | Name | Twist |
|-------:|------|-------|
| N | **The line, alone · prose** | The self-test is a short list, one line per service; the history is prose, one sentence per state. Facts to the right. |
| O | **The line, alone · ledger** | The self-test is a strip of outlined cards, one per service, outlined in the grade's colour; the history is a thread with a dot per state, the same dots the band uses. Facts to the right. |

Both share the top half exactly: title sentence, one line at the page's
own scale (rises up to 60 px), the earlier silences this week marked on
it. They differ only in how the lower half is set.

## Scenes (both directions prove all four)

1. quiet, and answers when tested — `n-quiet` / `o-quiet`
2. deaf on telnet (self-test failed) — `n-failed` / `o-failed`
3. silent, third time this week — `n-silent` / `o-silent`
4. the sweep night, from this canary — `n-night` / `o-night`

## Data story and palette

canary-iot, iot lane, 10.0.30.9, enrolled Wed 12 Aug 09:41 by tom,
mockingbird 0.4.1. Two short silences on Tue 1 Sep (11 min) and Thu 3 Sep
(1 min). Scenes 1–3 are Sat 5 Sep 22:04:31; scene 4 is Fri 12 Sep, the
round-5/6 sweep night seen from this one canary (198.51.100.7 on :445
every twenty minutes, 203.0.113.42 root/toor on ssh at 22:01).

Self-test grades, as the words on the page: *marked* (the probe's marker
came back in the event), *challenge-marked* (a signed answer to a
challenge, vnc), *attributed* (no marker can travel, the agent claims its
own probe and birdcage matches the claim). *Untested* is not a fault.

No new colour: `--ok` for answered, `--ink` for did not answer, `--ink-3`
for untested and the ticks. Lane colour for the line, as in the shell.

## Capture

`python3 gen.py`; `node capture.mjs` → `shots/<scene>.png`. All eight
shots inspected. Fixes this round: the two silence labels collided and
then the failed-run stem ran through one, so both labels sit left of
their marks on two rows; the failed-run words moved above the line to
clear the axis; O's history thread went to one line per entry to clear
the legend.

## Verdicts

Open.
