#!/usr/bin/env python3
"""Round 8: sign-in through gauntlet (#8, slice B). Three directions, P Q R, each the
way in to the ratified shell (ADR-0004, round 6 M) without restyling it. Palette,
type and chrome are round 6/7's, copied so the round stands alone.
Run here: python3 gen.py  ->  direction-p-on-the-line.html, direction-q-the-log.html,
direction-r-the-doors.html"""
import html
import random

# ---------------------------------------------------------------- data story
VER = '0.2.0'
DAY = 'sat 14 nov'
NOW = '09:18:04'
IP = '192.0.2.10'            # ada's laptop
SETUP = '7KQW-93HD-2MXF'     # the one-time setup code from the server log
KEY = 'JBSW Y3DP EHPK 3PXP JBSW Y3DP EHPK 3PXP'
RECOVERY = ['k7mq-4d2x', 'p3vn-8rtc', 'h2wd-6yqa', 'z9lf-1sbe', 'm4cr-7hjn',
            't6xp-2vgk', 'b8qn-5wmz', 'r1dk-9pft', 'w5hs-3lcy', 'g2tb-8nxv']
DECK = ['the door', 'the trace', 'visitors', 'audit log', 'settings']
SCENES = [('signin', 'sign in'), ('factor', 'second factor'), ('firstrun', 'first run'),
          ('enrol', 'enrol an authenticator'), ('codes', 'recovery codes, shown once'),
          ('timeout', 'timed out'), ('refused', 'refused'), ('locked', 'too many tries')]


def qr_modules(n=29, seed=8):
    """A deterministic placeholder: finder patterns and seeded modules. Not scannable."""
    rnd = random.Random(seed)
    g = [[0] * n for _ in range(n)]
    for (r0, c0) in [(0, 0), (0, n - 7), (n - 7, 0)]:
        for r in range(7):
            for c in range(7):
                edge = r in (0, 6) or c in (0, 6)
                core = 2 <= r <= 4 and 2 <= c <= 4
                g[r0 + r][c0 + c] = 1 if (edge or core) else 0
    for r in range(n):
        for c in range(n):
            infinder = (r < 8 and c < 8) or (r < 8 and c >= n - 8) or (r >= n - 8 and c < 8)
            if not infinder:
                g[r][c] = 1 if rnd.random() < .48 else 0
    for i in range(8, n - 8):
        g[6][i] = g[i][6] = 1 - (i % 2)
    return g


def qr_svg(size=174, cls='qr'):
    g = qr_modules()
    n = len(g)
    m = size / n
    rects = ''.join(f'<rect x="{c*m:.1f}" y="{r*m:.1f}" width="{m+.2:.1f}" height="{m+.2:.1f}"/>'
                    for r in range(n) for c in range(n) if g[r][c])
    return (f'<svg class="{cls}" width="{size}" height="{size}" viewBox="0 0 {size} {size}" role="img" '
            f'aria-label="QR code for the authenticator app (placeholder pattern)">{rects}</svg>')


def qr_text():
    g = qr_modules()
    n = len(g)
    rows = []
    for r in range(0, n, 2):
        top = g[r]
        bot = g[r + 1] if r + 1 < n else [0] * n
        rows.append(''.join('█' if t and b else '▀' if t else '▄' if b else ' ' for t, b in zip(top, bot)))
    return '\n'.join(rows)


# ---------------------------------------------------------------- shared css
BASE = """
  :root {
    --void: #06080e; --raised: #0f1422;
    --hair: rgba(160,185,230,.13); --hair-2: rgba(160,185,230,.26);
    --ink: #e9eefb; --ink-2: #97a4c4; --ink-3: #55628a; --accent: #9db8e8;
    --lan: #3987e5; --srv: #199e70; --iot: #c98500; --guest: #d76a9e;
    --ok: #37b364; --alarm: #ff5470; --now: #e8b05a;
    --sans: system-ui, -apple-system, "Segoe UI", sans-serif;
    --mono: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  }
  * { box-sizing: border-box; }
  html, body { margin: 0; }
  body { background: var(--void); color: var(--ink); font: 13.5px/1.5 var(--sans); -webkit-font-smoothing: antialiased; }
  .scene { position: relative; width: 1440px; height: 900px; margin: 0 auto 40px; overflow: hidden;
    background: radial-gradient(1000px 540px at 75% -15%, rgba(80,115,205,.07), transparent 60%), var(--void); border-bottom: 1px solid var(--hair-2); }
  .tag { position: absolute; left: 50%; transform: translateX(-50%); bottom: 0; font: 9.5px var(--mono); letter-spacing: .12em; color: var(--ink-3); z-index: 9; text-transform: uppercase; }
  .wordmark { position: absolute; top: 18px; left: 24px; font-weight: 800; font-size: 15px; letter-spacing: .04em; }
  .wordmark em { font-style: normal; color: var(--accent); }
  .ver { position: absolute; top: 20px; right: 40px; font: 11px var(--mono); color: var(--ink-3); }
  .ver b { color: var(--ink-2); font-weight: 500; }
  .deck { position: absolute; right: 8px; top: 50%; transform: translateY(-50%); display: flex; flex-direction: column; gap: 30px; align-items: center; }
  .deck span { writing-mode: sideways-lr; color: var(--ink-3); font: 500 9.5px var(--mono); letter-spacing: .22em; text-transform: uppercase; }
  .deck .on { color: var(--ink); font-size: 12px; letter-spacing: .26em; }
  .ibtn { position: absolute; left: 14px; bottom: 12px; width: 18px; height: 18px; border-radius: 50%; border: 1px solid var(--hair-2); color: var(--ink-3); font: italic 600 11px Georgia, serif; text-align: center; line-height: 16px; }
  input, button { font: inherit; color: inherit; }
  input { background: none; border: 0; outline: 0; padding: 0; margin: 0; }
  button { background: none; border: 0; padding: 0; margin: 0; cursor: pointer; }
  .ip { font-family: var(--mono); }
  .caret { display: inline-block; width: 1.5px; height: 1em; background: var(--accent); vertical-align: -.15em; margin-left: 1px; }
  @media (prefers-reduced-motion: no-preference) {
    .caret { animation: blink 1.1s steps(2, start) infinite; }
    @keyframes blink { to { visibility: hidden; } }
  }

  /* the dashboard behind the timed-out scene: round 6's quiet shell, flat */
  .behind { position: absolute; inset: 0; }
  .behind .tabs { position: absolute; top: 21px; left: 150px; display: flex; gap: 20px; font: 12px var(--sans); color: var(--ink-3); }
  .behind .tabs .on { color: var(--ink); }
  .behind .status { position: absolute; top: 20px; right: 40px; display: flex; gap: 16px; align-items: center; font: 11px var(--mono); color: var(--ink-2); }
  .behind .status .who { color: var(--ink-3); border: 1px solid var(--hair-2); border-radius: 999px; padding: 2px 10px; }
  .behind .ranges { display: flex; gap: 4px; } .behind .ranges span { color: var(--ink-3); padding: 2px 9px; border-radius: 4px; }
  .behind .ranges .on { color: var(--ink); background: var(--raised); border: 1px solid var(--hair-2); }
  .behind .grp { position: absolute; left: 54px; top: 74px; font: 600 9.5px var(--mono); letter-spacing: .16em; color: var(--ink-3); text-transform: uppercase; }
  .behind .hero { position: absolute; left: 54px; top: 96px; font: 500 26px/1.2 var(--sans); } .behind .hero b { color: var(--ok); }
  .behind .sub { position: absolute; left: 54px; top: 140px; width: 820px; font: 13px/1.55 var(--sans); color: var(--ink-2); }
  .behind svg.band { position: absolute; inset: 0; }
  .behind .bandlab { font: 600 10.5px var(--mono); } .behind .ax { font: 600 9.5px var(--mono); letter-spacing: .12em; fill: var(--ink-3); } .behind .ax.now { fill: var(--now); }
  .behind .tiles { position: absolute; left: 54px; top: 470px; display: flex; gap: 14px; }
  .behind .tile { --b: var(--lan); width: 300px; height: 96px; padding: 12px 14px; border: 1px solid var(--b); border-radius: 8px; background: var(--raised); }
  .behind .tile .n { font: 700 12px var(--mono); color: var(--b); } .behind .tile .s { font: 12px var(--sans); color: var(--ink); margin-top: 4px; }
  .behind .tile .p { font: 11px var(--mono); color: var(--ink-3); margin-top: 6px; }
  .behind .events { position: absolute; left: 54px; top: 600px; font: 600 9.5px var(--mono); letter-spacing: .16em; color: var(--ink-3); text-transform: uppercase; }
  .behind .events p { margin: 10px 0 0; font: italic 13px var(--sans); color: var(--ink-2); letter-spacing: 0; text-transform: none; }
  .behind .legend { position: absolute; left: 54px; bottom: 60px; font: 11px var(--sans); color: var(--ink-3); display: flex; gap: 22px; }
  .behind .foot { position: absolute; left: 0; right: 40px; bottom: 14px; text-align: center; font: 12.5px var(--sans); color: var(--ink-2); }
  .scrim { position: absolute; inset: 0; background: rgba(6,8,14,.74); }
"""


def behind():
    """The quiet dashboard as it was when the session idled out at 08:52."""
    lanes = [('canary-lan', 'lan', 'ssh 22 · smb 445 · http 80'), ('canary-srv', 'srv', 'ssh 22 · rdp 3389 · mysql 3306'),
             ('canary-iot', 'iot', 'telnet 23 · ssh 22 · smb 445'), ('canary-guest', 'guest', 'http 80 · ssh 22')]
    X0, X1, Y = 190, 1300, 300
    parts = []
    for i, (name, lane, _) in enumerate(lanes):
        y = Y + i * 12
        beats = ''.join(f'<circle cx="{x}" cy="{y+7}" r="2.4" fill="none" stroke="var(--{lane})" stroke-width="1" opacity=".7"/>'
                        for x in range(X0 + 10 + i * 7, 560, 28))
        ticks = ''.join(f'<line x1="{x}" y1="{y-2}" x2="{x}" y2="{y+2}" stroke="var(--{lane})" stroke-width="1" opacity=".6"/>'
                        for x in range(1000 + i * 9, X1, 40))
        parts.append(f'<text class="bandlab" x="{X0-12}" y="{y+3.5}" text-anchor="end" fill="var(--{lane})">{name}</text>'
                     f'<line x1="{X0}" y1="{y}" x2="{X1}" y2="{y}" stroke="var(--{lane})" stroke-width="1.5"/>{beats}{ticks}')
    ax = Y + 70
    parts.append(f'<line x1="{X0}" y1="{ax}" x2="{X1}" y2="{ax}" stroke="var(--hair-2)"/>')
    for x, t in [(X0, '14 d'), (560, '24 h'), (900, '1 h'), (1130, '15 m')]:
        parts.append(f'<line x1="{x}" y1="{ax-6}" x2="{x}" y2="{ax}" stroke="var(--hair-2)"/><text class="ax" x="{x}" y="{ax+16}">{t.upper()}</text>')
    parts.append(f'<text class="ax now" x="{X1}" y="{ax+16}" text-anchor="end">NOW · 08:52:10</text>'
                 f'<line x1="{X1}" y1="200" x2="{X1}" y2="{ax+4}" stroke="var(--now)" stroke-width="1.6"/>')
    tiles = ''.join(f'<div class="tile" style="--b:var(--{lane})"><div class="n">{name}</div><div class="s">quiet · phoning home</div><div class="p">{ports}</div></div>'
                    for name, lane, ports in lanes)
    rng = ''.join(f'<span{" class=on" if r == "14 d" else ""}>{r}</span>' for r in ['15 m', '1 h', '24 h', '14 d', '90 d'])
    return ('<div class="behind" aria-hidden="true">'
            '<div class="wordmark">BIRD<em>CAGE</em></div>'
            '<div class="tabs"><span class="on">the cage</span><span>visitors</span><span>audit log</span></div>'
            f'<div class="status"><div class="ranges">{rng}</div><span>QUIET · 4 of 4 phoning home</span><span>0 visitors · 14 d</span><span class="who">ada (admin)</span></div>'
            f'<div class="grp">the cage · {DAY} · 08:52:10</div>'
            '<div class="hero">The cage is <b>quiet</b>.</div>'
            '<div class="sub">Nothing has touched any of the four canaries in fourteen days. All four are phoning home every minute; the last self-test at 04:00 reached every service.</div>'
            f'<svg class="band" viewBox="0 0 1440 900">{"".join(parts)}</svg>'
            f'<div class="tiles">{tiles}</div>'
            '<div class="events">events · newest first<p>Nothing to list: no visitor in the last fourteen days.</p></div>'
            '<div class="legend"><span>— a line is a canary\'s heartbeat, unbroken</span><span>a rise is a visitor</span><span>a drop is silence</span><span>— the brink · now</span></div>'
            '<div class="foot">fourteen quiet days · nothing to act on</div>'
            '</div><div class="scrim"></div>')


def page(title, css, scenes):
    return (f'<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            f'<title>{title}</title>\n<style>{BASE}{css}</style>\n</head>\n<body>\n\n' + '\n\n'.join(scenes) + '\n\n</body>\n</html>\n')


def scene(sid, aria, body, tag, cls=''):
    return (f'<section class="scene {cls}" id="{sid}" role="region" aria-label="{html.escape(aria)}">\n{body}\n'
            f'  <div class="ibtn" aria-hidden="true">i</div>\n  <div class="tag">{tag}</div>\n</section>')


def deck(on='the door'):
    return '<nav class="deck" aria-label="sections">' + ''.join(f'<span{" class=on" if d == on else ""}>{d}</span>' for d in DECK) + '</nav>'


def chrome():
    return f'  <div class="wordmark">BIRD<em>CAGE</em></div>\n  <div class="ver">birdcage <b>{VER}</b></div>\n'


# ================================================================ P · on the line
P_CSS = """
  .p .grp { position: absolute; left: 54px; top: 92px; font: 600 9.5px var(--mono); letter-spacing: .16em; color: var(--ink-3); text-transform: uppercase; }
  .p .grp b { color: var(--ink-2); font-weight: 600; }
  .p .hero { position: absolute; left: 54px; top: 116px; font: 500 26px/1.2 var(--sans); color: var(--ink); letter-spacing: -.01em; }
  .p .hero b { font-weight: 700; } .p .hero .ok { color: var(--ok); } .p .hero .r { color: var(--ink); font-weight: 700; }
  .p .sub { position: absolute; left: 54px; top: 160px; width: 860px; font: 13px/1.55 var(--sans); color: var(--ink-2); }
  .p .sub b { color: var(--ink); font-weight: 600; } .p .sub .ip { font-size: 12.5px; color: var(--ink); }
  .p .log { position: absolute; left: 54px; top: 222px; font: 12px var(--mono); color: var(--ink-3); padding: 7px 12px; border-left: 2px solid var(--hair-2); }
  .p .log b { color: var(--ink); font-weight: 600; }
  .p .brink { position: absolute; left: 1300px; width: 2px; background: var(--now); border-radius: 1px; }
  .p .brink i { position: absolute; top: -18px; right: 8px; font: 600 9.5px var(--mono); letter-spacing: .06em; color: var(--now); font-style: normal; white-space: nowrap; }
  .p .lines { position: absolute; left: 54px; right: 140px; }
  .p .row { position: relative; height: 72px; }
  .p .row .lab { position: absolute; left: 0; top: 24px; width: 124px; text-align: right; font: 600 10.5px var(--mono); color: var(--ink-3); letter-spacing: .04em; }
  .p .row .lab b { color: var(--ink-2); font-weight: 600; }
  .p .row .ln { position: absolute; left: 136px; right: 0; top: 46px; height: 1px; background: var(--hair-2); }
  .p .row.live .ln { background: var(--ink); }
  .p .row.set .ln { background: var(--ink-3); }
  .p .row .val { position: absolute; left: 148px; top: 18px; font: 500 16px var(--mono); color: var(--ink); letter-spacing: .02em; }
  .p .row .val input { width: 520px; font: inherit; color: inherit; letter-spacing: inherit; }
  .p .row.set .val { color: var(--ink-2); }
  .p .row .val .dots { letter-spacing: .14em; }
  .p .row .val .digits { letter-spacing: .5em; font-size: 20px; } .p .row .val .digits .blank { color: var(--ink-3); }
  .p .row .after { position: absolute; right: 16px; top: 20px; font: 11.5px var(--mono); color: var(--ink-3); }
  .p .row .after.ok { color: var(--ok); }
  .p .row .hint { position: absolute; left: 148px; top: 52px; font: 11px var(--sans); color: var(--ink-3); }
  .p .row.half .ln { right: 50%; }
  /* a refusal: the line drops under the band and runs on dashed, the silence mark */
  .p .row.drop .ln { display: none; }
  .p .row svg.drop { position: absolute; left: 136px; right: 0; top: 30px; width: calc(100% - 136px); height: 42px; overflow: visible; }
  .p .row svg.drop path { fill: none; stroke: var(--ink); stroke-width: 1px; vector-effect: non-scaling-stroke; }
  .p .row svg.drop path.dash { stroke: var(--ink-3); stroke-dasharray: 4 4; }
  .p .row svg.drop circle { fill: var(--void); stroke: var(--ink); stroke-width: 1.2px; }
  .p .row .said { position: absolute; left: 148px; top: 60px; font: 600 12px var(--sans); color: var(--ink); white-space: nowrap; }
  .p .row .said span { color: var(--ink-3); font-weight: 400; margin-left: 10px; }
  .p .row.wait .lab, .p .row.wait .val { color: var(--ink-3); }
  .p .acts { position: absolute; left: 190px; right: 166px; display: flex; justify-content: space-between; align-items: center; }
  .p .acts .alt { display: flex; gap: 8px; }
  .p .pill { font: 600 11px var(--sans); color: var(--accent); border: 1px solid var(--hair-2); border-radius: 999px; padding: 4px 14px; white-space: nowrap; }
  .p .pill.go { color: var(--void); background: var(--accent); border-color: var(--accent); font-size: 12px; padding: 6px 18px; }
  .p .pill.quiet { color: var(--ink-3); } .p .pill.off { color: var(--ink-3); border-style: dashed; background: none; }
  .p .cd { position: absolute; left: 190px; font: 500 15px var(--mono); color: var(--ink); }
  .p .cd b { font-size: 34px; font-weight: 500; letter-spacing: .02em; margin-right: 14px; vertical-align: -3px; }
  .p .cd span { color: var(--ink-3); font: 12px var(--sans); }
  .p .qr { position: absolute; left: 54px; top: 288px; background: #fff; padding: 10px; border-radius: 6px; width: 194px; height: 194px; }
  .p .qr rect { fill: #06080e; }
  .p .qrcap { position: absolute; left: 54px; top: 490px; width: 194px; font: 11px/1.45 var(--sans); color: var(--ink-3); text-align: center; }
  .p .codes { position: absolute; left: 190px; display: grid; grid-template-columns: repeat(5, 190px); gap: 36px 24px; }
  .p .codes div { font: 500 16px var(--mono); color: var(--ink); letter-spacing: .04em; padding-bottom: 8px; border-bottom: 1px solid var(--ink); }
  .p .codes div small { display: block; font: 10.5px var(--mono); color: var(--ink-3); letter-spacing: .06em; margin-bottom: 4px; }
  .p .legend { position: absolute; left: 54px; right: 140px; bottom: 56px; font: 11px var(--sans); color: var(--ink-3); display: flex; gap: 22px; flex-wrap: wrap; }
  .p .legend .ln { display: inline-block; width: 22px; height: 0; border-top: 1.5px solid var(--ink); vertical-align: 3px; margin-right: 6px; opacity: .8; }
  .p .legend .gap { display: inline-block; width: 22px; height: 0; border-top: 1.5px dashed var(--ink-3); vertical-align: 3px; margin-right: 6px; }
  .p .legend .nw { color: var(--now); } .p .legend .nw i { display: inline-block; width: 0; height: 10px; border-left: 2px solid var(--now); vertical-align: -1px; margin-right: 6px; }
  .p .foot { position: absolute; left: 0; right: 40px; bottom: 14px; text-align: center; font: 12.5px var(--sans); color: var(--ink-2); }
  .p .foot b { color: var(--ink); font-weight: 600; }
  /* timed out: one band cut through the dimmed dashboard */
  .p .strip { position: absolute; left: 0; right: 0; top: 268px; height: 330px; background: rgba(6,8,14,.96); border-top: 1px solid var(--hair-2); border-bottom: 1px solid var(--hair-2); }
  .p .strip .grp { top: 30px; } .p .strip .hero { top: 54px; } .p .strip .sub { top: 98px; }
  .p .strip .lines { top: 136px; } .p .strip .acts { top: 236px; } .p .strip .brink { top: 24px; height: 270px; }
  @media (prefers-reduced-motion: no-preference) {
    .p .brink { animation: brink 2.4s ease-in-out infinite; } @keyframes brink { 50% { opacity: .55; } }
    .p .row svg.drop path { stroke-dasharray: 1200; stroke-dashoffset: 1200; animation: draw 1.4s ease-out forwards; }
    .p .row svg.drop path.dash { stroke-dasharray: 4 4; stroke-dashoffset: 0; animation: none; opacity: 0; animation: appear .4s 1s forwards; }
    @keyframes draw { to { stroke-dashoffset: 0; } } @keyframes appear { to { opacity: 1; } }
  }
"""


def p_row(lab, val, cls='', after='', hint='', extra=''):
    a = f'<span class="after{" ok" if after.startswith("accepted") else ""}">{after}</span>' if after else ''
    h = f'<span class="hint">{hint}</span>' if hint else ''
    return f'<div class="row {cls}"><span class="lab">{lab}</span><span class="ln"></span><span class="val">{val}</span>{a}{h}{extra}</div>'


def p_in(name, value, label, kind='text', live=False, width=None):
    c = '<span class="caret"></span>' if live else ''
    v = html.escape(value)
    inp = f'<input type="{kind}" name="{name}" value="{v}" aria-label="{label}" autocomplete="off">'
    return (c + inp) if (live and not value) else (inp + c)


def p_drop(said, note):
    svg = ('<svg class="drop" viewBox="0 0 1000 42" preserveAspectRatio="none" aria-hidden="true">'
           '<path d="M0 16 H300 C340 16 348 38 392 38"/><path class="dash" d="M392 38 H1000"/>'
           '<circle cx="300" cy="16" r="4" vector-effect="non-scaling-stroke"/></svg>')
    return f'{svg}<span class="said">{said}<span>{note}</span></span>'


def p_acts(primary, alts, top, primary_cls='go'):
    alt = ''.join(f'<button class="pill {c}">{t}</button>' for t, c in alts)
    st = f' style="top:{top}px"' if top is not None else ''
    return f'<div class="acts"{st}><div class="alt">{alt}</div><button class="pill {primary_cls}">{primary}</button></div>'


def p_legend(extra=''):
    return ('<div class="legend"><span><i class="ln"></i>a line is one thing to type; the words above it are yours</span>'
            '<span><i class="gap"></i>a dropped line is a refusal, in ink, never alarm</span>'
            f'<span class="nw"><i></i>the amber line is now: cross it to go in</span>{extra}</div>')


def p_foot(t):
    return f'<div class="foot">{t}</div>'


def build_p():
    S = []
    dots = '<span class="dots">••••••••••••</span>'
    brink = lambda top, h, t='now · ' + NOW: f'<div class="brink" style="top:{top}px;height:{h}px" aria-hidden="true"><i>{t}</i></div>'

    # 1 sign in
    body = (chrome() + deck() +
            f'<div class="grp">the cage · {DAY} · {NOW} · <b>sign in</b></div>'
            '<div class="hero">Say who you are.</div>'
            '<div class="sub">Birdcage is watching four canaries. Nothing they have seen is shown until you are in. '
            f'You are <span class="ip">{IP}</span>; this is the first time this address has come to the door today.</div>'
            + brink(250, 270) +
            '<div class="lines" style="top:270px">'
            + p_row('who', p_in('user', 'ada', 'username'), 'live')
            + p_row('password', p_in('pass', '', 'password', 'password', live=True), 'live')
            + '</div>'
            + p_acts('sign in ▸', [('use a passkey', ''), ('sign in with SSO', 'quiet')], 440)
            + p_legend() + p_foot(f'<span class="ip">{IP}</span> → the cage · birdcage {VER} · sessions end after a day idle'))
    S.append(scene('p-signin', 'P, on the line: sign in', body, f'P · on the line · scene 1 · sign in', 'p'))

    # 2 second factor
    body = (chrome() + deck() +
            f'<div class="grp">the cage · {DAY} · 09:18:09 · <b>sign in · second factor</b></div>'
            '<div class="hero"><b>ada</b>, one more thing.</div>'
            '<div class="sub">A code from your authenticator app: six digits, a new one every thirty seconds. '
            'If the phone is gone, a recovery code opens the same door, once.</div>'
            + brink(250, 340, 'now · 09:18:09') +
            '<div class="lines" style="top:270px">'
            + p_row('who', 'ada', 'set', after='accepted · 09:18:09')
            + p_row('password', dots, 'set', after='accepted · 09:18:09')
            + p_row('code', '<span class="digits">417<span class="blank">···</span></span><span class="caret"></span>', 'live half', hint='from the authenticator app · this one is good for another 19 s')
            + '</div>'
            + p_acts('continue ▸', [('use a recovery code instead', 'quiet')], 512)
            + p_legend() + p_foot(f'<span class="ip">{IP}</span> → the cage · birdcage {VER} · <b>ada</b> last signed in thu 13 nov 09:41'))
    S.append(scene('p-factor', 'P, on the line: second factor', body, 'P · on the line · scene 2 · second factor', 'p'))

    # 3 first run
    body = (chrome() + deck() +
            f'<div class="grp">first run · {DAY} · {NOW} · <b>no accounts yet</b></div>'
            '<div class="hero">No one has keys yet.</div>'
            f'<div class="sub">Birdcage {VER} started at 09:12 with no accounts, and printed a setup code in its server log. '
            'Paste it here, then choose the first admin\'s name and password. The code is good for fifteen minutes, once.</div>'
            f'<div class="log" aria-label="the line from the server log">09:12:04 birdcage {VER} · no accounts · <b>setup code {SETUP}</b> · valid until 09:27 · printed once, in the server log</div>'
            + brink(292, 380) +
            '<div class="lines" style="top:300px">'
            + p_row('setup code', p_in('setup', SETUP, 'setup code'), 'live', after='from the server log')
            + p_row('first admin', p_in('user', 'ada', 'username for the first admin'), 'live', hint='lower-case letters, digits, dots and dashes · this account is the admin')
            + p_row('password', p_in('pass', '••••••••••••••', 'password'), 'live', hint='twelve characters or more · a phrase is fine')
            + p_row('again', p_in('pass2', '•••••••', 'password, again', live=True), 'live')
            + '</div>'
            + p_acts('create the first admin ▸', [('sign in with SSO instead', 'quiet')], 588)
            + p_legend() + p_foot(f'<span class="ip">{IP}</span> → the cage · birdcage {VER} · until an admin exists the cage shows nothing and answers 503'))
    S.append(scene('p-firstrun', 'P, on the line: first run', body, 'P · on the line · scene 3 · first run', 'p'))

    # 4 enrol
    body = (chrome() + deck() +
            f'<div class="grp">first run · {DAY} · 09:18:14 · <b>ada · second factor</b></div>'
            '<div class="hero">Now a second thing you hold.</div>'
            '<div class="sub">Every password account carries a second factor. Scan the square with an authenticator app, or type the key into it; '
            'then prove it with one code. A passkey can be added later from settings.</div>'
            + qr_svg() + '<div class="qrcap">scan with any authenticator app<br>(a placeholder pattern in this mock-up)</div>'
            + brink(272, 330, 'now · 09:18:14') +
            '<div class="lines" style="top:280px;left:230px">'
            + p_row('key', f'<span class="ip">{KEY}</span>', 'set', hint='type this instead of scanning')
            + p_row('account', 'birdcage:ada', 'set', after='time-based · 6 digits · 30 s')
            + p_row('code', '<span class="digits"><span class="blank">······</span></span><span class="caret"></span>', 'live half', hint='the first code the app shows')
            + '</div>'
            + '<div class="acts" style="top:528px;left:366px"><div class="alt"></div><button class="pill go">confirm ▸</button></div>'
            + p_legend() + p_foot(f'<b>ada</b> · birdcage {VER} · the key is shown once; if the app loses it, an admin resets it from the users page'))
    S.append(scene('p-enrol', 'P, on the line: enrol an authenticator', body, 'P · on the line · scene 4 · enrol an authenticator', 'p'))

    # 5 recovery codes
    codes = ''.join(f'<div><small>{i+1:02d}</small>{c}</div>' for i, c in enumerate(RECOVERY))
    body = (chrome() + deck() +
            f'<div class="grp">first run · {DAY} · 09:18:41 · <b>ada · recovery codes</b></div>'
            '<div class="hero">Ten recovery codes. <b>Shown once.</b></div>'
            '<div class="sub">Each opens the door one time if the phone is gone. Keep them somewhere that is not this computer: a password manager, or paper. '
            'When they are gone, an admin can issue ten more; birdcage never shows these again.</div>'
            + brink(250, 370, 'now · 09:18:41') +
            f'<div class="codes" style="top:300px">{codes}</div>'
            + p_acts('I have kept them · go in ▸', [('copy', ''), ('download as text', ''), ('print', 'quiet')], 540)
            + p_legend() + p_foot(f'<b>ada</b> · birdcage {VER} · 10 of 10 codes unused'))
    S.append(scene('p-codes', 'P, on the line: recovery codes shown once', body, 'P · on the line · scene 5 · recovery codes, shown once', 'p'))

    # 6 timed out
    body = (behind() + deck('the trace') +
            '<div class="strip">'
            f'<div class="grp">the cage · {DAY} · {NOW} · <b>session ended · idle since 08:52</b></div>'
            '<div class="hero"><b>ada</b>, you were away. The dashboard is <b>26 minutes</b> behind.</div>'
            '<div class="sub">Your session idled out at 08:52. Your password carries on from where you were; what is behind this strip has not moved since, and nothing is lost.</div>'
            '<div class="brink" aria-hidden="true"><i>now · 09:18:04</i></div>'
            '<div class="lines">'
            + p_row('password', p_in('pass', '', 'password', 'password', live=True), 'live', after='<span class="ip">ada</span> · second factor not asked again on this device')
            + '</div>'
            + p_acts('carry on ▸', [('sign in as someone else', 'quiet')], None)
            + '</div>')
    S.append(scene('p-timeout', 'P, on the line: timed out over the dimmed dashboard', body, 'P · on the line · scene 6 · timed out', 'p'))

    # 7 refused
    body = (chrome() + deck() +
            f'<div class="grp">the cage · {DAY} · 09:18:07 · <b>sign in · refused</b></div>'
            '<div class="hero">That is not <b>ada</b>\'s password.</div>'
            '<div class="sub">Four more tries before a five-minute wait. A refusal is drawn the way the trace draws silence: the line drops and runs on in ink. '
            'Nothing here says whether the name exists.</div>'
            + brink(250, 270, 'now · 09:18:07') +
            '<div class="lines" style="top:270px">'
            + p_row('who', p_in('user', 'ada', 'username'), 'live')
            + p_row('password', p_in('pass', '', 'password', 'password', live=True), 'live drop', extra=p_drop('refused at 09:18:07', '4 tries left · the wait is per name and per address'))
            + '</div>'
            + p_acts('try again ▸', [('use a passkey', ''), ('sign in with SSO', 'quiet')], 440)
            + p_legend() + p_foot(f'<span class="ip">{IP}</span> → the cage · birdcage {VER} · 1 refusal in this five minutes'))
    S.append(scene('p-refused', 'P, on the line: refused, wrong password', body, 'P · on the line · scene 7 · refused', 'p'))

    # 8 too many tries
    body = (chrome() + deck() +
            f'<div class="grp">the cage · {DAY} · 09:18:48 · <b>sign in · too many tries</b></div>'
            '<div class="hero">Too many tries. <b>Wait.</b></div>'
            f'<div class="sub">Five wrong passwords for <b>ada</b> from <span class="ip">{IP}</span> inside five minutes. The door opens again for this name and this address at <b>09:23:00</b>; '
            'anyone else, <b>wren</b> included, can still sign in. A passkey or SSO is not counted.</div>'
            + brink(250, 330, 'now · 09:18:48') +
            '<div class="lines" style="top:270px">'
            + p_row('who', 'ada', 'wait drop', extra='<svg class="drop" viewBox="0 0 1000 42" preserveAspectRatio="none" aria-hidden="true"><path class="dash" style="opacity:1;animation:none" d="M0 16 H1000"/></svg>')
            + p_row('password', '', 'wait drop', extra='<svg class="drop" viewBox="0 0 1000 42" preserveAspectRatio="none" aria-hidden="true"><path class="dash" style="opacity:1;animation:none" d="M0 16 H1000"/></svg>'
                    '<span class="said">5 refusals between 09:18:07 and 09:18:48<span>the last at 09:18:48</span></span>')
            + '</div>'
            '<div class="cd" style="top:432px"><b>4:12</b> until the door opens for ada from here <span>· counting down · the page will let you type when it does</span></div>'
            + p_acts('sign in', [('use a passkey', ''), ('sign in with SSO', 'quiet')], 500, 'off')
            + p_legend() + p_foot(f'<span class="ip">{IP}</span> → the cage · birdcage {VER} · 5 of 5 refusals in this five minutes · the audit log has them'))
    S.append(scene('p-locked', 'P, on the line: too many tries, wait', body, 'P · on the line · scene 8 · too many tries', 'p'))
    return page('Birdcage · round 8 · P · on the line', P_CSS, S)


# ================================================================ Q · the log
Q_CSS = """
  .q .col { position: absolute; left: 54px; top: 110px; width: 1120px; font: 14px/30px var(--mono); color: var(--ink); }
  .q .col::before { content: ''; position: absolute; left: 100px; top: -8px; bottom: -8px; width: 1px; background: var(--hair); }
  .q .l { display: grid; grid-template-columns: 112px 1fr; min-height: 30px; }
  .q .l .t { color: var(--ink-3); font-size: 12px; letter-spacing: .02em; }
  .q .l .t.live { color: var(--now); }
  .q .l .x { white-space: nowrap; }
  .q .l .x i { font-style: normal; color: var(--ink-3); } .q .l .x b { font-weight: 600; } .q .l .x .ok { color: var(--ok); }
  .q .l .x .dim { color: var(--ink-2); } .q .l .x .code { color: var(--accent); font-weight: 600; }
  .q .l.gap { min-height: 18px; }
  .q .l.in .x { display: flex; align-items: center; gap: 14px; }
  .q .l.in .k { color: var(--ink-2); width: 220px; }
  .q .f { display: inline-flex; align-items: center; height: 26px; min-width: 300px; padding: 0 9px; border: 1px solid var(--hair-2); background: var(--raised); line-height: 24px; }
  .q .f input { width: 100%; font: inherit; }
  .q .f.live { border-color: var(--accent); }
  .q .f.set { border-color: transparent; background: none; padding-left: 0; color: var(--ink-2); min-width: 0; }
  .q .f.wide { min-width: 460px; } .q .f.short { min-width: 120px; }
  .q .f.off { border-style: dashed; color: var(--ink-3); background: none; }
  .q .digits { letter-spacing: .4em; font-size: 16px; } .q .digits .blank { color: var(--ink-3); }
  .q .n { color: var(--ink-3); font-size: 12px; margin-left: 4px; }
  .q .acts .x { display: flex; gap: 18px; align-items: center; }
  .q .b { display: inline-block; font: 600 13px/26px var(--mono); color: var(--ink); border: 1px solid var(--ink); padding: 0 12px; background: none; }
  .q .b.go { background: var(--ink); color: var(--void); }
  .q .b.off { color: var(--ink-3); border-style: dashed; }
  .q .a { font: 13px var(--mono); color: var(--accent); background: none; }
  .q .a::before { content: '· '; color: var(--ink-3); }
  .q .a.quiet { color: var(--ink-2); }
  .q .said { color: var(--ink); font-weight: 600; } .q .said i { font-weight: 400; }
  .q .qrt { display: grid; grid-template-columns: auto 1fr; gap: 30px; align-items: start; margin: 6px 0 10px; }
  .q .qrs { background: #fff; padding: 8px; width: 184px; height: 184px; box-sizing: content-box; display: block; } .q .qrs rect { fill: #06080e; }
  .q .kv { font: 14px/28px var(--mono); }
  .q .kv div { display: grid; grid-template-columns: 110px 1fr; } .q .kv i { font-style: normal; color: var(--ink-2); }
  .q .rc { display: grid; grid-template-columns: repeat(5, 150px); gap: 4px 30px; margin: 4px 0 10px; font: 15px/30px var(--mono); }
  .q .rc span i { font-style: normal; color: var(--ink-3); font-size: 11px; margin-right: 10px; }
  .q .big { font-size: 28px; font-weight: 500; line-height: 40px; }
  .q .aside { position: absolute; left: 54px; bottom: 56px; width: 760px; font: 12px/1.55 var(--sans); color: var(--ink-3); }
  .q .aside b { color: var(--ink-2); font-weight: 600; }
  .q .foot { position: absolute; left: 0; right: 40px; bottom: 14px; text-align: center; font: 12px var(--mono); color: var(--ink-3); }
  .q .foot b { color: var(--ink-2); font-weight: 500; }
  /* timed out: the log rises as a drawer from the bottom of the dimmed dashboard */
  .q .drawer { position: absolute; left: 0; right: 0; bottom: 0; height: 330px; background: rgba(6,8,14,.97); border-top: 1px solid var(--hair-2); }
  .q .drawer .col { top: 36px; } .q .drawer .foot { bottom: 14px; }
  .q .drawer .handle { position: absolute; top: -1px; left: 54px; font: 600 9.5px var(--mono); letter-spacing: .16em; color: var(--ink-3); text-transform: uppercase; padding: 6px 0; }
  @media (prefers-reduced-motion: no-preference) {
    .q .l.new { animation: rise .5s ease-out both; } @keyframes rise { from { opacity: 0; transform: translateY(6px); } }
    .q .drawer { animation: up .5s ease-out both; } @keyframes up { from { transform: translateY(40px); opacity: 0; } }
  }
"""


def ql(t, x, cls=''):
    tc = ' live' if 'new' in cls else ''
    return f'<div class="l {cls}"><span class="t{tc}">{t}</span><span class="x">{x}</span></div>'


def qin(k, field, note=''):
    n = f'<span class="n">{note}</span>' if note else ''
    return f'<div class="l in"><span class="t"></span><span class="x"><span class="k">{k}</span>{field}{n}</span></div>'


def qf(name, value, label, kind='text', cls='live', live=True):
    c = '<span class="caret"></span>' if live else ''
    return f'<span class="f {cls}"><input type="{kind}" name="{name}" value="{html.escape(value)}" aria-label="{label}" autocomplete="off">{c}</span>'


def qacts(primary, alts, go=True):
    pb = f'<button class="b {"go" if go else "off"}">{"▸ " if go else ""}{primary}</button>'
    ab = ''.join(f'<button class="a {c}">{t}</button>' for t, c in alts)
    return f'<div class="l acts"><span class="t"></span><span class="x">{pb}{ab}</span></div>'


def qgap():
    return '<div class="l gap"></div>'


def q_foot(t):
    return f'<div class="foot">{t}</div>'


def q_aside(t):
    return f'<div class="aside">{t}</div>'


def build_q():
    S = []
    start = [ql('09:12:04', f'birdcage <b>{VER}</b> · started · listening on :8443'),
             ql('09:12:04', '4 canaries enrolled · 2 accounts · the trace is <span class="ok">quiet</span>'),
             ql('09:12:05', '<i>what the canaries have seen is behind the door; this is the door</i>'), qgap()]
    col = lambda *ls: '<div class="col" role="log" aria-label="the door, as a log">' + ''.join(ls) + '</div>'

    # 1 sign in
    body = (chrome() + deck() + col(*start,
            ql(NOW, f'<span class="ip">{IP}</span> at the door · <b>who are you?</b>', 'new'),
            qin('name', qf('user', 'ada', 'username', live=False)),
            qin('password', qf('pass', '', 'password', 'password')),
            qacts('sign in', [('use a passkey', ''), ('sign in with sso', 'quiet')]))
            + q_aside('Every line is a line birdcage also writes to its own log, in the same words. Nothing above the door is shown until you are in; the time on the left is the server\'s.')
            + q_foot(f'birdcage <b>{VER}</b> · the door · {DAY} {NOW}'))
    S.append(scene('q-signin', 'Q, the log: sign in', body, 'Q · the log · scene 1 · sign in', 'q'))

    # 2 second factor
    body = (chrome() + deck() + col(*start,
            ql(NOW, f'<span class="ip">{IP}</span> at the door · who are you?'),
            qin('name', qf('user', 'ada', 'username', cls='set', live=False)),
            qin('password', '<span class="f set">••••••••••••</span>', '<span class="ok">accepted 09:18:09</span>'),
            qgap(),
            ql('09:18:09', '<b>ada</b> · one more thing · <i>the code from your authenticator app</i>', 'new'),
            qin('code', '<span class="f live short"><span class="digits">417<span class="blank">···</span></span><span class="caret"></span></span>', 'six digits · a new one every 30 s · this one has 19 s left'),
            qacts('continue', [('use a recovery code instead', 'quiet')]))
            + q_aside('A recovery code is one of the ten shown when the authenticator was set up; each works once. <b>ada</b> last signed in thu 13 nov 09:41 from this address.')
            + q_foot(f'birdcage <b>{VER}</b> · the door · {DAY} 09:18:09'))
    S.append(scene('q-factor', 'Q, the log: second factor', body, 'Q · the log · scene 2 · second factor', 'q'))

    # 3 first run
    body = (chrome() + deck() + col(
            ql('09:12:04', f'birdcage <b>{VER}</b> · started · listening on :8443'),
            ql('09:12:04', '<b>no accounts</b> · setup required · the cage answers 503 to everything else'),
            ql('09:12:04', f'setup code <span class="code">{SETUP}</span> · valid until 09:27 · <i>this line is also in the server log; paste the code below</i>'),
            qgap(),
            ql(NOW, f'<span class="ip">{IP}</span> at the door · <b>first run</b> · <i>the first account is the admin</i>', 'new'),
            qin('setup code', qf('setup', SETUP, 'setup code', cls='live', live=False), 'from the server log'),
            qin('first admin', qf('user', 'ada', 'username for the first admin', live=False), 'lower-case letters, digits, dots, dashes'),
            qin('password', qf('pass', '••••••••••••••', 'password', 'password', live=False), 'twelve characters or more'),
            qin('again', qf('pass2', '•••••••', 'password, again', 'password')),
            qacts('create the first admin', [('sign in with sso instead', 'quiet')]))
            + q_aside('The setup code is printed once, when birdcage starts with no accounts; restart birdcage for a new one. After this account, an authenticator app and ten recovery codes follow before the cage is shown.')
            + q_foot(f'birdcage <b>{VER}</b> · the door · first run · {DAY} {NOW}'))
    S.append(scene('q-firstrun', 'Q, the log: first run', body, 'Q · the log · scene 3 · first run', 'q'))

    # 4 enrol
    kv = (f'<div class="kv"><div><i>key</i><span>{KEY}</span></div><div><i>account</i><span>birdcage:ada</span></div>'
          '<div><i>type</i><span>time-based · sha1 · 6 digits · 30 s</span></div>'
          '<div><i>or</i><span class="dim">scan the square with any authenticator app <span class="n">(a placeholder pattern in this mock-up)</span></span></div></div>')
    body = (chrome() + deck() + col(
            ql(NOW, f'<span class="ip">{IP}</span> at the door · first run · <b>ada</b> created · <span class="ok">admin</span>'),
            qgap(),
            ql('09:18:14', '<b>ada</b> · a second thing you hold · <i>every password account carries one</i>', 'new'),
            f'<div class="l"><span class="t"></span><span class="x"><div class="qrt">{qr_svg(168, "qrs")}{kv}</div></span></div>',
            qin('code from the app', '<span class="f live short"><span class="digits"><span class="blank">······</span></span><span class="caret"></span></span>', 'the first code it shows'),
            qacts('confirm', []))
            + q_aside('The key is shown once. If the app loses it, an admin clears the second factor from the users page and this step runs again. A passkey can be added later from settings.')
            + q_foot(f'birdcage <b>{VER}</b> · the door · first run · {DAY} 09:18:14'))
    S.append(scene('q-enrol', 'Q, the log: enrol an authenticator', body, 'Q · the log · scene 4 · enrol an authenticator', 'q'))

    # 5 recovery codes
    rc = '<div class="rc">' + ''.join(f'<span><i>{i+1:02d}</i>{c}</span>' for i, c in enumerate(RECOVERY)) + '</div>'
    body = (chrome() + deck() + col(
            ql('09:18:14', '<b>ada</b> · a second thing you hold'),
            ql('09:18:41', 'authenticator <span class="ok">confirmed</span> · code accepted'),
            qgap(),
            ql('09:18:41', '<b>ten recovery codes</b> · shown once · <i>each opens the door one time if the phone is gone</i>', 'new'),
            f'<div class="l"><span class="t"></span><span class="x">{rc}</span></div>',
            ql('', '<i>keep them somewhere that is not this computer: a password manager, or paper. birdcage never shows them again; an admin can issue ten more.</i>'),
            qacts('i have kept them · go in', [('copy', ''), ('download as text', ''), ('print', 'quiet')]))
            + q_foot(f'birdcage <b>{VER}</b> · the door · first run · {DAY} 09:18:41 · 10 of 10 unused'))
    S.append(scene('q-codes', 'Q, the log: recovery codes shown once', body, 'Q · the log · scene 5 · recovery codes, shown once', 'q'))

    # 6 timed out
    body = (behind() + deck('the trace') +
            '<div class="drawer"><div class="handle">the door</div>' + col(
            ql('08:52:10', '<b>ada</b> · idle for a day · the session ended · <i>the dashboard above stopped here</i>'),
            ql(NOW, '<b>ada</b>, you were away · the dashboard is <b>26 min</b> behind · <i>your password carries on from where you were; nothing is lost</i>', 'new'),
            qin('password', qf('pass', '', 'password', 'password'), 'second factor not asked again on this device'),
            qacts('carry on', [('sign in as someone else', 'quiet')]))
            + q_foot(f'birdcage <b>{VER}</b> · the door · {DAY} {NOW}') + '</div>')
    S.append(scene('q-timeout', 'Q, the log: timed out, drawer over the dimmed dashboard', body, 'Q · the log · scene 6 · timed out', 'q'))

    # 7 refused
    body = (chrome() + deck() + col(*start,
            ql(NOW, f'<span class="ip">{IP}</span> at the door · who are you?'),
            ql('09:18:07', '<span class="said">refused · that is not ada\'s password <i>· 4 tries left before a five-minute wait · whether the name exists is not said</i></span>', 'new'),
            qin('name', qf('user', 'ada', 'username', live=False)),
            qin('password', qf('pass', '', 'password', 'password')),
            qacts('try again', [('use a passkey', ''), ('sign in with sso', 'quiet')]))
            + q_aside('A refusal is a line in ink, not alarm: the trace keeps red for visitors. Five refusals for one name from one address inside five minutes close the door to that pair until the window passes.')
            + q_foot(f'birdcage <b>{VER}</b> · the door · {DAY} 09:18:07 · 1 refusal in this five minutes'))
    S.append(scene('q-refused', 'Q, the log: refused, wrong password', body, 'Q · the log · scene 7 · refused', 'q'))

    # 8 too many tries
    body = (chrome() + deck() + col(*start,
            ql(NOW, f'<span class="ip">{IP}</span> at the door · who are you?'),
            ql('09:18:07', '<span class="said">refused</span> · ada · 4 tries left'),
            ql('09:18:19', '<span class="said">refused</span> · ada · 3 tries left'),
            ql('09:18:28', '<span class="said">refused</span> · ada · 2 tries left'),
            ql('09:18:39', '<span class="said">refused</span> · ada · 1 try left'),
            ql('09:18:48', f'<span class="said">refused</span> · ada · <b>too many tries</b> · the door is closed to <b>ada</b> from <span class="ip">{IP}</span> until <b>09:23:00</b>', 'new'),
            qgap(),
            ql('', '<span class="big">4:12</span> <span class="n">until it opens · counting down · the fields wake up when it does</span>'),
            qin('name', '<span class="f off"><input value="ada" aria-label="username" disabled></span>'),
            qin('password', '<span class="f off"><input type="password" value="" aria-label="password" disabled></span>'),
            qacts('sign in', [('use a passkey', ''), ('sign in with sso', 'quiet')], go=False))
            + q_aside('The wait is for this name from this address only: <b>wren</b>, or ada from another machine, can still sign in. A passkey or SSO is not counted. All five refusals are in the audit log.')
            + q_foot(f'birdcage <b>{VER}</b> · the door · {DAY} 09:18:48 · 5 of 5 refusals in this five minutes'))
    S.append(scene('q-locked', 'Q, the log: too many tries, wait', body, 'Q · the log · scene 8 · too many tries', 'q'))
    return page('Birdcage · round 8 · Q · the log', Q_CSS, S)


# ================================================================ R · the doors
R_CSS = """
  .r .hall { position: absolute; left: 0; right: 0; top: 150px; display: flex; justify-content: center; align-items: stretch; gap: 14px; }
  .r .spine { width: 46px; border: 1px solid var(--hair-2); border-radius: 10px; display: flex; align-items: center; justify-content: center; position: relative; }
  .r .spine span { writing-mode: sideways-lr; font: 600 10.5px var(--mono); letter-spacing: .22em; text-transform: uppercase; color: var(--ink-3); white-space: nowrap; }
  .r .spine.done { border-color: var(--ok); } .r .spine.done span { color: var(--ok); }
  .r .spine.done::before { content: '✓'; position: absolute; top: 10px; left: 0; right: 0; text-align: center; font: 700 11px var(--mono); color: var(--ok); }
  .r .spine.ahead { border-style: dashed; border-color: var(--hair); }
  .r .spine.cage { border-color: var(--hair-2); } .r .spine.cage span { color: var(--ink-2); }
  .r .door { width: 760px; min-height: 440px; border: 1px solid var(--accent); border-radius: 12px; background: var(--raised); padding: 46px 52px 40px; position: relative; display: flex; flex-direction: column; }
  .r .door.wide { width: 920px; }
  .r .door .step { font: 600 9.5px var(--mono); letter-spacing: .16em; color: var(--ink-3); text-transform: uppercase; }
  .r .door .step b { color: var(--ink-2); font-weight: 600; }
  .r .door h2 { margin: 12px 0 10px; font: 500 30px/1.15 var(--sans); letter-spacing: -.01em; color: var(--ink); }
  .r .door h2 b { font-weight: 700; } .r .door h2 .ok { color: var(--ok); }
  .r .door .sub { font: 14px/1.55 var(--sans); color: var(--ink-2); max-width: 60ch; }
  .r .door .sub b { color: var(--ink); font-weight: 600; } .r .door .sub .ip { color: var(--ink); font-size: 13px; }
  .r .fields { margin-top: 28px; display: grid; grid-template-columns: 1fr 1fr; gap: 24px 36px; }
  .r .fields.one { grid-template-columns: 1fr; max-width: 420px; }
  .r .fld { position: relative; }
  .r .fld label { display: block; font: 600 9.5px var(--mono); letter-spacing: .16em; color: var(--ink-3); text-transform: uppercase; margin-bottom: 6px; }
  .r .fld .box { height: 44px; border-bottom: 1px solid var(--hair-2); display: flex; align-items: center; font: 18px var(--sans); color: var(--ink); }
  .r .fld .box input { width: 100%; font: inherit; }
  .r .fld.live .box { border-bottom-color: var(--accent); }
  .r .fld .box .mono { font: 500 17px var(--mono); letter-spacing: .03em; }
  .r .fld .box .digits { font: 500 26px var(--mono); letter-spacing: .5em; } .r .fld .box .digits .blank { color: var(--ink-3); }
  .r .fld .note { margin-top: 6px; font: 11.5px var(--sans); color: var(--ink-3); } .r .fld .note.ok { color: var(--ok); }
  .r .fld.set .box { border-bottom-color: transparent; color: var(--ink-2); }
  .r .fld.off .box { border-bottom-style: dashed; color: var(--ink-3); }
  .r .said { margin-top: 18px; font: 600 14px var(--sans); color: var(--ink); padding: 10px 14px; border: 1px solid var(--ink); border-radius: 8px; }
  .r .said span { color: var(--ink-2); font-weight: 400; }
  .r .acts { margin-top: auto; display: flex; align-items: center; gap: 12px; padding-top: 28px; }
  .r .go { font: 600 14px var(--sans); color: var(--void); background: var(--accent); border-radius: 999px; padding: 11px 24px; }
  .r .go.off { background: none; color: var(--ink-3); border: 1px dashed var(--hair-2); }
  .r .alt { font: 600 12px var(--sans); color: var(--accent); border: 1px solid var(--hair-2); border-radius: 999px; padding: 7px 16px; }
  .r .alt.quiet { color: var(--ink-3); border-color: transparent; }
  .r .acts .sp { flex: 1; }
  .r .acts .meta { font: 11.5px var(--mono); color: var(--ink-3); }
  .r .log { margin-top: 18px; font: 12px var(--mono); color: var(--ink-3); padding: 8px 12px; border-left: 2px solid var(--hair-2); }
  .r .log b { color: var(--ink); font-weight: 600; }
  .r .two { display: grid; grid-template-columns: 214px 1fr; gap: 40px; margin-top: 26px; align-items: start; }
  .r .qr { background: #fff; padding: 10px; border-radius: 6px; width: 214px; height: 214px; } .r .qr rect { fill: #06080e; }
  .r .qrcap { margin-top: 8px; font: 11px/1.45 var(--sans); color: var(--ink-3); text-align: center; width: 214px; }
  .r .codes { margin-top: 26px; display: grid; grid-template-columns: repeat(5, 1fr); gap: 20px 24px; }
  .r .codes div { font: 500 18px var(--mono); color: var(--ink); letter-spacing: .04em; padding: 10px 0 10px; border-top: 1px solid var(--hair-2); }
  .r .codes div small { display: block; font: 10px var(--mono); color: var(--ink-3); letter-spacing: .1em; margin-bottom: 6px; }
  .r .wait { margin-top: 24px; display: flex; align-items: baseline; gap: 16px; }
  .r .wait b { font: 500 44px var(--mono); color: var(--ink); } .r .wait span { font: 13px var(--sans); color: var(--ink-2); }
  .r .door.refused { border-color: var(--ink); }
  .r .door.locked { border-color: var(--ink-3); border-style: dashed; background: transparent; }
  .r .foot { position: absolute; left: 0; right: 0; bottom: 14px; text-align: center; font: 12.5px var(--sans); color: var(--ink-2); }
  .r .foot b { color: var(--ink); font-weight: 600; }
  .r .hall.side { justify-content: flex-end; padding-right: 56px; top: 196px; } .r .hall.side .spine { background: var(--void); }
  .r .hall.side .door { width: 620px; }
  @media (prefers-reduced-motion: no-preference) {
    .r .door { animation: slide .55s cubic-bezier(.2,.7,.2,1) both; } @keyframes slide { from { opacity: 0; transform: translateX(40px); } }
    .r .door.refused { animation: slide .55s both, shake .5s .55s ease-in-out; } @keyframes shake { 20%, 60% { transform: translateX(-6px); } 40%, 80% { transform: translateX(6px); } }
  }
"""


def spine(t, cls=''):
    return f'<div class="spine {cls}" aria-label="{html.escape(t)}"><span>{t}</span></div>'


def rfld(label, box, cls='', note=''):
    n = f'<div class="note{" ok" if note.startswith("accepted") else ""}">{note}</div>' if note else ''
    return f'<div class="fld {cls}"><label>{label}</label><div class="box">{box}</div>{n}</div>'


def rin(name, value, label, kind='text', live=False):
    c = '<span class="caret"></span>' if live else ''
    inp = f'<input type="{kind}" name="{name}" value="{html.escape(value)}" aria-label="{label}" autocomplete="off">'
    return (c + inp) if (live and not value) else (inp + c)


def racts(primary, alts, meta='', go='go'):
    ab = ''.join(f'<button class="alt {c}">{t}</button>' for t, c in alts)
    m = f'<span class="meta">{meta}</span>' if meta else ''
    return f'<div class="acts"><button class="{go}">{primary}</button>{ab}<span class="sp"></span>{m}</div>'


def door(step, h2, sub, inner, acts, cls=''):
    return f'<div class="door {cls}"><div class="step">{step}</div><h2>{h2}</h2><div class="sub">{sub}</div>{inner}{acts}</div>'


def hall(parts, cls=''):
    return f'<div class="hall {cls}" aria-label="the doors">{"".join(parts)}</div>'


def r_foot(t):
    return f'<div class="foot">{t}</div>'


def build_r():
    S = []
    # 1 sign in
    d = door(f'the door · {DAY} · {NOW}', 'Say who you are.',
             f'Birdcage is watching four canaries. Nothing they have seen is shown until you are through. You are <span class="ip">{IP}</span>.',
             '<div class="fields">' + rfld('who', rin('user', 'ada', 'username'), 'live') + rfld('password', rin('pass', '', 'password', 'password', live=True), 'live') + '</div>',
             racts('sign in ▸', [('use a passkey', ''), ('sign in with SSO', 'quiet')], 'then a code, then the cage'))
    body = chrome() + hall([d, spine('a code', 'ahead'), spine('the cage', 'cage')]) + r_foot(f'birdcage {VER} · each door you pass folds to the left; the ones ahead wait on the right')
    S.append(scene('r-signin', 'R, the doors: sign in', body, 'R · the doors · scene 1 · sign in', 'r'))

    # 2 second factor
    d = door(f'the door · {DAY} · 09:18:09 · second of three', '<b>ada</b>, one more thing.',
             'A code from your authenticator app: six digits, a new one every thirty seconds. If the phone is gone, a recovery code opens this door once.',
             '<div class="fields one">' + rfld('code', '<span class="digits">417<span class="blank">···</span></span><span class="caret"></span>', 'live', 'this one is good for another 19 s') + '</div>',
             racts('continue ▸', [('use a recovery code instead', 'quiet')], 'ada last signed in thu 13 nov 09:41'))
    body = chrome() + hall([spine('ada · password', 'done'), d, spine('the cage', 'cage')]) + r_foot(f'birdcage {VER} · password accepted 09:18:09')
    S.append(scene('r-factor', 'R, the doors: second factor', body, 'R · the doors · scene 2 · second factor', 'r'))

    # 3 first run
    d = door(f'first run · {DAY} · {NOW} · first of four', 'No one has keys yet.',
             f'Birdcage {VER} started at 09:12 with no accounts and printed a setup code in its server log. Paste it, then name the first admin. The code is good for fifteen minutes, once.',
             f'<div class="log">09:12:04 birdcage {VER} · no accounts · <b>setup code {SETUP}</b> · valid until 09:27</div>'
             '<div class="fields">' + rfld('setup code', f'<span class="mono">{SETUP}</span>', 'live', 'from the server log')
             + rfld('first admin', rin('user', 'ada', 'username for the first admin'), 'live', 'lower-case letters, digits, dots and dashes')
             + rfld('password', rin('pass', '••••••••••••••', 'password', 'password'), 'live', 'twelve characters or more; a phrase is fine')
             + rfld('again', rin('pass2', '•••••••', 'password, again', 'password', live=True), 'live') + '</div>',
             racts('create the first admin ▸', [('sign in with SSO instead', 'quiet')], 'then an authenticator, then recovery codes'))
    body = chrome() + hall([d, spine('an authenticator', 'ahead'), spine('recovery codes', 'ahead'), spine('the cage', 'cage')]) + r_foot(f'birdcage {VER} · until an admin exists the cage shows nothing and answers 503')
    S.append(scene('r-firstrun', 'R, the doors: first run', body, 'R · the doors · scene 3 · first run', 'r'))

    # 4 enrol
    inner = ('<div class="two"><div>' + qr_svg(214) + '<div class="qrcap">scan with any authenticator app<br>(a placeholder pattern in this mock-up)</div></div>'
             '<div><div class="fields one" style="margin-top:0;max-width:none">'
             + rfld('or type the key', f'<span class="mono">{KEY}</span>', 'set', 'account birdcage:ada · time-based · 6 digits · 30 s')
             + rfld('the first code the app shows', '<span class="digits"><span class="blank">······</span></span><span class="caret"></span>', 'live')
             + '</div></div></div>')
    d = door(f'first run · {DAY} · 09:18:14 · second of four', 'Now a second thing you hold.',
             'Every password account carries a second factor. Scan the square or type the key into an authenticator app, then prove it with one code. A passkey can be added later.',
             inner, racts('confirm ▸', [], 'the key is shown once'), 'wide')
    body = chrome() + hall([spine('setup code', 'done'), spine('ada · admin', 'done'), d, spine('recovery codes', 'ahead'), spine('the cage', 'cage')]) + r_foot(f'birdcage {VER} · if the app loses the key, an admin resets it from the users page')
    S.append(scene('r-enrol', 'R, the doors: enrol an authenticator', body, 'R · the doors · scene 4 · enrol an authenticator', 'r'))

    # 5 recovery codes
    codes = '<div class="codes">' + ''.join(f'<div><small>{i+1:02d}</small>{c}</div>' for i, c in enumerate(RECOVERY)) + '</div>'
    d = door(f'first run · {DAY} · 09:18:41 · third of four', 'Ten recovery codes. <b>Shown once.</b>',
             'Each opens the door one time if the phone is gone. Keep them somewhere that is not this computer: a password manager, or paper. Birdcage never shows them again; an admin can issue ten more.',
             codes, racts('I have kept them · go in ▸', [('copy', ''), ('download as text', ''), ('print', 'quiet')], '10 of 10 unused'), 'wide')
    body = chrome() + hall([spine('setup code', 'done'), spine('ada · admin', 'done'), spine('authenticator', 'done'), d, spine('the cage', 'cage')]) + r_foot(f'birdcage {VER} · the last door before the cage')
    S.append(scene('r-codes', 'R, the doors: recovery codes shown once', body, 'R · the doors · scene 5 · recovery codes, shown once', 'r'))

    # 6 timed out
    d = door(f'the door · {DAY} · {NOW} · session ended', '<b>ada</b>, you were away.',
             'Your session idled out at 08:52; the dashboard behind is <b>26 minutes</b> behind. Your password carries on from where you were, and nothing is lost.',
             '<div class="fields one">' + rfld('password', rin('pass', '', 'password', 'password', live=True), 'live', 'second factor not asked again on this device') + '</div>',
             racts('carry on ▸', [('sign in as someone else', 'quiet')]))
    body = behind() + hall([spine('ada · signed in thu 09:41', 'done'), d], 'side')
    S.append(scene('r-timeout', 'R, the doors: timed out, a door over the dimmed dashboard', body, 'R · the doors · scene 6 · timed out', 'r'))

    # 7 refused
    d = door(f'the door · {DAY} · 09:18:07 · refused', 'That is not <b>ada</b>\'s password.',
             'Four more tries before a five-minute wait. Whether the name exists is not said.',
             '<div class="fields">' + rfld('who', rin('user', 'ada', 'username'), 'live') + rfld('password', rin('pass', '', 'password', 'password', live=True), 'live') + '</div>'
             '<div class="said">refused at 09:18:07 <span>· 4 tries left · the wait is per name and per address</span></div>',
             racts('try again ▸', [('use a passkey', ''), ('sign in with SSO', 'quiet')], '1 refusal in this five minutes'), 'refused')
    body = chrome() + hall([d, spine('a code', 'ahead'), spine('the cage', 'cage')]) + r_foot(f'birdcage {VER} · the door outline turns to ink on a refusal, the way the trace draws a fault')
    S.append(scene('r-refused', 'R, the doors: refused, wrong password', body, 'R · the doors · scene 7 · refused', 'r'))

    # 8 too many tries
    d = door(f'the door · {DAY} · 09:18:48 · too many tries', 'Too many tries. <b>Wait.</b>',
             f'Five wrong passwords for <b>ada</b> from <span class="ip">{IP}</span> inside five minutes. The door opens again for this name from this address at <b>09:23:00</b>; anyone else, <b>wren</b> included, can still sign in.',
             '<div class="wait"><b>4:12</b><span>until it opens · counting down · the fields wake up when it does</span></div>'
             '<div class="fields">' + rfld('who', 'ada', 'off') + rfld('password', '', 'off', '5 refusals, 09:18:07 to 09:18:48 · all in the audit log') + '</div>',
             racts('sign in', [('use a passkey', ''), ('sign in with SSO', 'quiet')], 'a passkey or SSO is not counted', 'go off'), 'locked')
    body = chrome() + hall([d, spine('a code', 'ahead'), spine('the cage', 'cage')]) + r_foot(f'birdcage {VER} · a closed door is drawn dashed, the way the trace draws a silent canary')
    S.append(scene('r-locked', 'R, the doors: too many tries, wait', body, 'R · the doors · scene 8 · too many tries', 'r'))
    return page('Birdcage · round 8 · R · the doors', R_CSS, S)


if __name__ == '__main__':
    for name, fn in [('direction-p-on-the-line.html', build_p), ('direction-q-the-log.html', build_q), ('direction-r-the-doors.html', build_r)]:
        with open(name, 'w') as f:
            f.write(fn())
        print(name)
