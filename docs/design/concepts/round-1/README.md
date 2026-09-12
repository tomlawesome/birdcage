# Design round 1 — dashboard shell (#3)

Three directions for the birdcage dashboard, all in mikroview's Atlas II
visual language (tokens copied from `mikroview/frontend/src/app.css`;
ADR-0003). Self-contained HTML, no build step. Open `index.html` or a
direction file; scenes are `section.scene` blocks with ids.

## Directions

| Letter | Name   | Idea | Hit detail |
|-------:|--------|------|------------|
| A | **Aviary** | Fleet first: one card per canary (24 h density strip, count, last-10-min), stream of hits below. | Glass drawer on the right. |
| B | **Ledger** | Feed first, closest to mikroview: 216 px left rail with groups (Live / Canaries / Act / Admin), one table with day separators, the sweep as a banner. | Expands in place under the row. |
| C | **Perch**  | Visitor first: one row per source address with a plain-English story, canaries touched, timeline, count. Fleet in a side column. | Visitor expands to its hits; a hit opens a sheet below. |

## Scenes (every direction proves all three)

1. `*-start` — landing, live, sweep in progress.
2. `*-filter` — narrowed to source 203.0.113.42 (C: the visitor opened).
3. `*-hit` — the 21:56:58 canary-srv ssh hit opened: kv, same source across the fleet, raw OpenCanary JSON, `lookback in mikroview` (mikroview#29, read-only token).

## Data story (fixed across rounds)

Four canaries: canary-lan 10.0.10.250, canary-srv 10.0.20.250, canary-iot
10.0.30.250, canary-guest 10.0.40.250 (lane colours lan/srv/iot/guest).
Tonight 2026-09-12: 203.0.113.42 sweeps all four 21:55–22:04 (ssh, then
mysql on srv; 7 hits; not in CrowdSec). 198.51.100.7 has hit canary-iot smb
every ~20 min for 6 days (221 hits; community-blocked). 10.0.40.23, a guest
device, fetched `/` then `/admin` on canary-lan http at 19:11 (never
auto-blocked: inside, #33). 192.0.2.88 tried anonymous ftp on canary-srv
yesterday 03:18, once. Totals: 232 hits today, 4 visitors. Logged in as
`tom (admin)`.

## Palette

Lane palette (`#3987e5 #199e70 #c98500 #d76a9e`) validated with the dataviz
validator on surface `#06080e`: ALL CHECKS PASS (worst CVD ΔE 8.4 protan,
normal-vision 18.9). Status colours alarm/warn/log are mikroview's and are
never used as series.

## Capture

`node capture.mjs` (borrows mikroview's playwright) writes `shots/<scene>.png`
at 1600×1000 @2x. Every shot was inspected; fixes this round: wrapping
drawer buttons (A), detail row overflowing the table (B), IP column wrap (C).

## Verdicts

_Pending owner review._
