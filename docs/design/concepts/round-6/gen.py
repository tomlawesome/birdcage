#!/usr/bin/env python3
"""Round 6: the trace with the boxed tiles (round 5, J) kept, and the box
outline itself carrying the canary's colour instead of a bar down the side.
Generates direction-l-trace-outlined.html (every outline in its canary's
colour) and direction-m-trace-outlined-ink.html (same, but a silent canary's
outline goes to dashed ink like its dropped line). Run here: python3 gen.py"""
from datetime import date, timedelta
from math import log2

# ---------------------------------------------------------------- data story (rounds 1–4)
NOW = 22*3600 + 4*60 + 31
QUIET_DAY, NIGHT_DAY = date(2026, 9, 5), date(2026, 9, 12)
lane = {'lan': 'var(--lan)', 'srv': 'var(--srv)', 'iot': 'var(--iot)', 'guest': 'var(--guest)'}
kind = {'sw': 'var(--sweep)', 'rp': 'var(--repeat)', 'in': 'var(--inside)', 'tc': 'var(--touch)'}
beat_off = {'lan': 9, 'srv': 41, 'iot': 22, 'guest': 3}
SILENT_LAST = 372
sweep = [(0, 'guest', 'root / 123456'), (29, 'guest', 'admin / admin'), (164, 'iot', 'root / toor'),
         (429, 'srv', 'mysql root / (empty)'), (453, 'srv', 'root / password'), (531, 'lan', 'root / root'),
         (532, 'lan', 'session · libssh2')]
repeat = [321 + d*86400 + k*1200 for d in range(6) for k in range(37)][:221]
ports = {'lan': 'ssh 22 · http 80 · smb 445', 'srv': 'ssh 22 · mysql 3306 · ftp 21', 'iot': 'telnet 23 · ssh 22 · smb 445', 'guest': 'telnet 23 · ssh 22 · http 80'}

# what rises from each line on the sweep night: (kind, [ago...], label line 1, label line 2)
NIGHT_HITS = {
    'lan': [('sw', [531, 532], 'root / root · session libssh2', '203.0.113.42 → canary-lan · 21:55'),
            ('in', [10389, 10407], '/ then /admin', '10.0.40.23 → canary-lan :80 · 19:11')],
    'srv': [('sw', [429, 453], 'mysql root / (empty) · root / password', '203.0.113.42 → canary-srv · 21:56'),
            ('tc', [153951], 'anonymous ftp, once', '192.0.2.88 → canary-srv :21 · yesterday 03:18')],
    'iot': [('sw', [164], 'root / toor', '203.0.113.42 → canary-iot · 22:01'),
            ('rp', repeat, '37 knocks tonight, every 20 min · six nights', '198.51.100.7 → canary-iot :445')],
    'guest': [('sw', [0, 29], 'root / 123456 · admin / admin', '203.0.113.42 → canary-guest · 22:04')],
}

# ---------------------------------------------------------------- axis
X0, X1 = 190, 1520
SEGS = [(0, 900, 300), (900, 3600, 180), (3600, 86400, 200), (86400, 1209600, 200)]
SC = (X1-X0)/880


def cx(ago):
    x = X1
    for a0, a1, w in SEGS:
        if ago <= a1:
            return x - (ago-a0)/(a1-a0)*w*SC
        x -= w*SC
    return X0


def axis(y, day):
    out = []
    for lab, ago in [('14 d', 1209600), ('24 h', 86400), ('1 h', 3600), ('15 m', 900)]:
        x = cx(ago)
        out.append(f'<text x="{x:.1f}" y="{y}" class="ax">{lab}</text><line x1="{x:.1f}" y1="{y-16}" x2="{x:.1f}" y2="{y-10}" class="axt"/>')
    out.append(f'<text x="{X1}" y="{y}" class="ax now" text-anchor="end">NOW · 22:04:31</text>')
    for k in range(14):
        x = cx(NOW + k*86400)
        out.append(f'<line x1="{x:.1f}" y1="{y-14}" x2="{x:.1f}" y2="{y-10}" class="axt" opacity=".6"/>')
        if k in (4, 8, 12):
            d = day - timedelta(days=k)
            out.append(f'<text x="{x:.1f}" y="{y+16}" class="axs">{d.strftime("%a %-d %b").lower()}</text>')
    out.append(f'<text x="{(cx(86400)+cx(3600))/2:.1f}" y="{y+16}" class="axs">23 hours, compressed</text>')
    out.append(f'<text x="{(cx(900)+X1)/2:.1f}" y="{y+16}" class="axs">the last quarter hour, stretched</text>')
    return '\n'.join(out)


# ---------------------------------------------------------------- the trace
BAND = [290, 302, 314, 326]          # four lines, 12 px apart
PITCH = 12


def beats(y, off, since=0):
    out, a = [], off
    while a < 900:
        if a >= since:
            out.append(f'<rect x="{cx(a)-.7:.1f}" y="{y-2}" width="1.4" height="4" fill="var(--ink-3)" opacity=".55"/>')
        a += 60
    return '\n'.join(out)


def clusters(agos, gap=6):
    """merge hits whose x positions are within `gap` px → [(x_from, x_to, count)]"""
    xs = sorted(cx(a) for a in agos)
    out = []
    for x in xs:
        if out and x - out[-1][1] <= gap:
            out[-1][1] = x
            out[-1][2] += 1
        else:
            out.append([x, x, 1])
    return out


def bump(x0, x1, y, h, col, w=16):
    """a smooth rise from the line: up over `w`, flat across the cluster, down over `w`"""
    a, b = x0 - w, min(x1 + w, X1)
    d = (f'M{a:.1f},{y} C{a+w*.55:.1f},{y} {x0-w*.45:.1f},{y-h} {x0:.1f},{y-h} '
         f'L{x1:.1f},{y-h} C{x1+(b-x1)*.45:.1f},{y-h} {b-(b-x1)*.55:.1f},{y} {b:.1f},{y}')
    return (f'<path d="{d}" fill="{col}" fill-opacity=".14" stroke="none"/>'
            f'<path d="{d}" fill="none" stroke="{col}" stroke-width="1.5" stroke-linejoin="round"/>')


CH = 6.4   # px per mono character at 10.5px
LH = 28    # a two-line label's height


def label_box(x, l1, l2):
    """where a label centred on x would sit: (anchor, anchor_x, x_from, x_to)"""
    w = max(len(l1)+2, len(l2)*.9)*CH
    if x + w/2 > X1:
        return 'end', X1, X1-w, X1
    if x - w/2 < X0:
        return 'start', X0, X0, X0+w
    return 'middle', x, x-w/2, x+w/2


def label(anchor, xx, y, col, l1, l2):
    return (f'<text x="{xx:.1f}" y="{y-16}" class="bl" text-anchor="{anchor}"><tspan fill="{col}">✱ </tspan>{l1}</text>'
            f'<text x="{xx:.1f}" y="{y-4}" class="bl dim" text-anchor="{anchor}">{l2}</text>')


def trace(hits=None, silent=False):
    parts = []
    hits = hits or {}
    rises = []  # [x_from, x_to, y, kind, l1, l2, labelled]
    for y, c in zip(BAND, lane):
        if silent and c == 'iot':
            xs = cx(SILENT_LAST)
            yd = BAND[-1] + 18
            parts.append(f'<line x1="{X0}" y1="{y}" x2="{xs:.1f}" y2="{y}" stroke="{lane[c]}" stroke-width="1.2" opacity=".6"/>')
            parts.append(f'<path d="M{xs:.1f},{y} C{xs+10:.1f},{y} {xs+8:.1f},{yd} {xs+20:.1f},{yd}" fill="none" stroke="var(--ink-3)" stroke-width="1.2"/>')
            parts.append(f'<line x1="{xs+20:.1f}" y1="{yd}" x2="{X1}" y2="{yd}" stroke="var(--ink-3)" stroke-width="1" stroke-dasharray="2 5" opacity=".8"/>')
            parts.append(beats(y, beat_off[c], since=SILENT_LAST))
            parts.append(f'<circle cx="{xs:.1f}" cy="{y}" r="3.6" fill="var(--void)" stroke="{lane[c]}" stroke-width="1.4"/>')
            parts.append(f'<text x="{xs-10:.1f}" y="{yd+3}" class="bl" text-anchor="end">canary-iot dropped out · last heartbeat <tspan fill="var(--ink)">21:58:19</tspan> · silent 6 m 12 s</text>')
        else:
            parts.append(f'<line x1="{X0}" y1="{y}" x2="{X1}" y2="{y}" stroke="{lane[c]}" stroke-width="1.2" opacity=".6"/>')
            parts.append(beats(y, beat_off[c]))
        parts.append(f'<text x="{X0-10}" y="{y+3}" class="bandlab" fill="{lane[c]}" text-anchor="end">canary-{c}</text>')
        for k, agos, l1, l2 in hits.get(c, []):
            cl = clusters(agos)
            widest = max(range(len(cl)), key=lambda i: (cl[i][1]-cl[i][0], cl[i][2]))
            for i, (xa, xb, n) in enumerate(cl):
                rises.append([xa, xb, y, k, l1, l2, i == widest])
    # unlabelled clusters are low ripples; a labelled rise climbs until its words clear its neighbours'
    rises.sort(key=lambda r: r[0])
    placed = []  # (x_from, x_to, top, bottom) of labels already on the page
    for r in rises:
        xa, xb, y, k, l1, l2, lab = r
        if not lab:
            parts.append(bump(xa, xb, y, 16, kind[k], 12))
            continue
        w = max(len(l1)+2, len(l2)*.9)*CH
        h = 34
        while True:
            bw = 14 + h*.2
            mid = (xa+xb)/2
            # where the words may sit: on top, hanging left of the rise, hanging right — first free wins.
            # the stretched quarter hour is crowded, so there they always hang left, at the apex.
            cands = [('end', xa-bw-6)] if mid > X1-300 else [label_box(mid, l1, l2)[:2], ('end', xa-bw-6), ('start', min(xb, X1)+bw+6)]
            free = None
            for anchor, ax in cands:
                bx0, bx1 = (ax-w, ax) if anchor == 'end' else (ax, ax+w) if anchor == 'start' else (ax-w/2, ax+w/2)
                if bx0 < X0-140 or bx1 > X1:
                    continue
                if not any(bx0 < px1+8 and bx1 > px0-8 and (y-h-LH) < pb+6 and (y-h) > pt-6 for px0, px1, pt, pb in placed):
                    free = (anchor, ax, bx0, bx1)
                    break
            if free:
                anchor, ax, bx0, bx1 = free
                break
            h += 30
        placed.append((bx0, bx1, y-h-LH, y-h))
        placed.append((xa-bw, min(xb+bw, X1), y-h, y))
        parts.append(bump(xa, xb, y, h, kind[k], bw))
        parts.append(label(anchor, ax, y-h, kind[k], l1, l2))
    top = min([BAND[0]-60] + [pt-10 for _, _, pt, _ in placed])
    parts.append(f'<line x1="{X1}" y1="{top:.0f}" x2="{X1}" y2="{BAND[-1]+40}" class="brink"/>')
    return parts


# ---------------------------------------------------------------- chrome
CSS = """
  :root {
    --void: #06080e; --raised: #0f1422;
    --hair: rgba(160,185,230,.13); --hair-2: rgba(160,185,230,.26);
    --ink: #e9eefb; --ink-2: #97a4c4; --ink-3: #55628a; --accent: #9db8e8;
    --lan: #3987e5; --srv: #199e70; --iot: #c98500; --guest: #d76a9e;
    --ok: #37b364; --alarm: #ff5470; --now: #e8b05a;
    --sweep: #ff5470; --repeat: #ff9e64; --inside: #f072c8; --touch: #b8c56a;
    --sans: system-ui, -apple-system, "Segoe UI", sans-serif;
    --mono: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  }
  * { box-sizing: border-box; }
  html, body { margin: 0; }
  body { background: var(--void); color: var(--ink); font: 13.5px/1.5 var(--sans); -webkit-font-smoothing: antialiased; }
  .scene { position: relative; width: 1600px; height: 1000px; margin: 0 auto 40px; overflow: hidden;
    background: radial-gradient(1100px 600px at 75% -15%, rgba(80,115,205,.07), transparent 60%), var(--void); border-bottom: 1px solid var(--hair-2); }
  .tag { position: absolute; left: 50%; transform: translateX(-50%); bottom: 0; font: 9.5px var(--mono); letter-spacing: .12em; color: var(--ink-3); z-index: 9; }
  .wordmark { position: absolute; top: 18px; left: 24px; font-weight: 800; font-size: 15px; letter-spacing: .04em; }
  .wordmark em { font-style: normal; color: var(--accent); }
  .tabs { position: absolute; top: 21px; left: 150px; display: flex; gap: 20px; font: 12px var(--sans); color: var(--ink-3); }
  .tabs .on { color: var(--ink); position: relative; }
  .tabs .on::after { content: ''; position: absolute; left: 0; right: 0; bottom: -4px; height: 1px; background: var(--accent); }
  .status { position: absolute; top: 20px; right: 40px; display: flex; gap: 16px; align-items: center; font: 11px var(--mono); color: var(--ink-2); }
  .status .dot { display: inline-block; width: 7px; height: 7px; border-radius: 50%; background: var(--ok); margin-right: 5px; vertical-align: 1px; }
  .status .dot.off { background: none; border: 1.5px solid var(--ink-2); animation: none; }
  .status .flag { color: var(--alarm); } .status .flag b { color: var(--void); background: var(--alarm); border-radius: 9px; padding: 0 7px; font-weight: 700; font-size: 10.5px; }
  .status .mute { color: var(--ink); font-weight: 700; }
  .status .who { color: var(--ink-3); border: 1px solid var(--hair-2); border-radius: 999px; padding: 2px 10px; }
  .ranges { display: flex; gap: 4px; margin-right: 8px; } .ranges span { font: 11px var(--mono); color: var(--ink-3); padding: 2px 9px; border-radius: 4px; }
  .ranges .on { color: var(--ink); background: var(--raised); border: 1px solid var(--hair-2); }
  .deck { position: absolute; right: 8px; top: 50%; transform: translateY(-50%); display: flex; flex-direction: column; gap: 30px; align-items: center; }
  .deck span { writing-mode: sideways-lr; color: var(--ink-3); font: 500 9.5px var(--mono); letter-spacing: .22em; }
  .deck .on { color: var(--ink); font-size: 12px; letter-spacing: .26em; }
  .ibtn { position: absolute; left: 14px; bottom: 12px; width: 18px; height: 18px; border-radius: 50%; border: 1px solid var(--hair-2); color: var(--ink-3); font: italic 600 11px Georgia, serif; text-align: center; line-height: 16px; }

  .score { position: absolute; inset: 0; pointer-events: none; }
  .ax { font: 600 9.5px var(--mono); letter-spacing: .12em; fill: var(--ink-3); text-transform: uppercase; }
  .ax.now { fill: var(--now); letter-spacing: .06em; }
  .axs { font: 9px var(--sans); fill: var(--ink-3); text-anchor: middle; opacity: .8; }
  .axt { stroke: var(--hair-2); }
  .brink { stroke: var(--now); stroke-width: 1.6; }
  .bandlab { font: 600 9.5px var(--mono); }
  .bl { font: 10.5px var(--mono); fill: var(--ink); } .bl.dim { fill: var(--ink-3); font-size: 9.5px; }

  .grp { position: absolute; left: 54px; font: 600 9.5px var(--mono); letter-spacing: .16em; color: var(--ink-3); text-transform: uppercase; }
  .grp b { color: var(--ink-2); font-weight: 600; } .grp .r { color: var(--alarm); }
  .hero { position: absolute; left: 54px; font: 500 26px/1.2 var(--sans); color: var(--ink); letter-spacing: -.01em; }
  .hero b { font-weight: 700; } .hero .ok { color: var(--ok); } .hero .r { color: var(--alarm); }
  .sub { position: absolute; left: 54px; width: 900px; font: 13px/1.55 var(--sans); color: var(--ink-2); }
  .sub b { color: var(--ink); font-weight: 600; } .sub .ip { font: 12.5px var(--mono); color: var(--ink); }
  .quiet-line { position: absolute; left: 54px; font: italic 13px/1.5 var(--sans); color: var(--ink-3); }
  .acts { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
  .pill { font: 600 11px var(--sans); color: var(--accent); border: 1px solid var(--hair-2); border-radius: 999px; padding: 3px 12px; white-space: nowrap; }
  .pill.quiet { color: var(--ink-3); }

  /* the canary tiles */
  .tiles { position: absolute; left: 54px; right: 80px; display: grid; grid-template-columns: repeat(4, 1fr); gap: 18px; }
  .tile { --c: var(--ink-2); position: relative; padding: 14px 16px 12px; }
  .tile .n { font: 700 12.5px var(--mono); color: var(--c); }
  .tile .n small { font-weight: 500; color: var(--ink-3); margin-left: 8px; }
  .tile .st { margin-top: 6px; padding-right: 96px; font: 11px var(--mono); color: var(--ink-2); }
  .tile .st .ok { color: var(--ok); } .tile .st .al { color: var(--alarm); font-weight: 700; } .tile .st .rp { color: var(--repeat); font-weight: 700; }
  .tile .st .off { color: var(--ink); font-weight: 700; }
  .tile .pt { margin-top: 8px; font: 10px var(--mono); color: var(--ink-3); }
  .tile .big { position: absolute; right: 16px; top: 12px; font: 600 20px var(--sans); color: var(--ink); letter-spacing: -.02em; }
  .tile .big small { display: block; font: 9px var(--mono); color: var(--ink-3); letter-spacing: .12em; text-transform: uppercase; text-align: right; font-weight: 600; }
  .tile.k-lan { --c: var(--lan); } .tile.k-srv { --c: var(--srv); } .tile.k-iot { --c: var(--iot); } .tile.k-guest { --c: var(--guest); }
  .tile .acts { margin-top: 10px; }

  /* the events */
  .row { position: absolute; left: 40px; right: 80px; height: 70px; display: grid; grid-template-columns: 92px 132px 1fr auto; column-gap: 16px; align-items: center; padding-left: 14px; border-bottom: 1px solid var(--hair); }
  .row::before { content: ''; position: absolute; left: 0; top: 10px; bottom: 10px; width: 3px; border-radius: 2px; background: var(--k); }
  .row.k-sw { --k: var(--sweep); } .row.k-rp { --k: var(--repeat); } .row.k-in { --k: var(--inside); } .row.k-tc { --k: var(--touch); } .row.k-off { --k: var(--ink-2); }
  .row .t { font: 11px var(--mono); color: var(--ink); } .row .t small { display: block; font: 10px var(--mono); color: var(--ink-3); }
  .row .kind { font: 700 11px var(--mono); letter-spacing: .06em; color: var(--k); white-space: nowrap; }
  .row .kind small { display: block; font: 10px var(--mono); color: var(--ink-3); letter-spacing: 0; margin-top: 3px; font-weight: 500; }
  .row .who { font: 12.5px var(--sans); color: var(--ink-2); line-height: 1.45; }
  .row .who .ip { font: 12.5px var(--mono); color: var(--ink); } .row .who b { color: var(--ink); font-weight: 600; }

  .legend { position: absolute; left: 54px; right: 80px; font: 11px var(--sans); color: var(--ink-3); display: flex; gap: 22px; flex-wrap: wrap; }
  .legend i { display: inline-block; width: 8px; height: 8px; border-radius: 50%; vertical-align: -1px; margin-right: 5px; }
  .legend .ln { display: inline-block; width: 22px; height: 0; border-top: 1.5px solid var(--lan); vertical-align: 3px; margin-right: 6px; opacity: .7; }
  .legend .gap { display: inline-block; width: 22px; height: 0; border-top: 1.5px dashed var(--ink-3); vertical-align: 3px; margin-right: 6px; }
  .legend .nw { color: var(--now); }
  .foot { position: absolute; left: 0; right: 40px; bottom: 14px; display: flex; justify-content: center; gap: 60px; font: 12.5px var(--sans); color: var(--ink-2); }
  .foot b { color: var(--ink); font-weight: 600; } .foot .r { color: var(--alarm); } .foot .ok { color: var(--ok); font-weight: 600; }
  @media (prefers-reduced-motion: no-preference) { .status .dot { animation: pulse 1.8s ease-in-out infinite; } .status .dot.off { animation: none; } @keyframes pulse { 50% { opacity: .4; } } }
"""
L_CSS = """
  .tile { background: var(--raised); border: 1px solid var(--c); border-radius: 8px; }
"""
M_CSS = L_CSS + """
  .tile.silent { border-color: var(--ink-3); border-style: dashed; background: transparent; }
"""

STATUS = {
    'quiet': '<span><span class="dot"></span>QUIET · 4 of 4 phoning home</span><span>◎ 0 visitors · 14 d</span>',
    'silent': '<span><span class="dot off"></span>3 of 4 phoning home · <span class="mute">canary-iot silent 6 m</span></span><span>◎ 0 visitors · 14 d</span>',
    'night': '<span><span class="dot"></span>LIVE · 4 canaries</span><span class="flag">⚑ <b>1</b></span><span>◎ 4 visitors</span>',
}
DECK = ['THE TRACE', 'VISITORS', 'AUDIT LOG', 'SETTINGS']
TABS = ['the cage', 'visitors', 'audit log']
LEGEND = ('<span><span class="ln"></span>a line is a canary\'s heartbeat, unbroken</span><span><span class="gap"></span>a drop is silence</span>'
          '<span>a rise is a visitor, its words at the top, by kind: <i style="background:var(--sweep)"></i>sweep <i style="background:var(--repeat)"></i>repeat '
          '<i style="background:var(--inside)"></i>from inside <i style="background:var(--touch)"></i>one touch</span>'
          '<span>dim marks are single heartbeats where the axis is stretched</span><span class="nw">— the brink · now</span>')


def chrome(status):
    rng = ''.join(f'<span{" class=on" if r == "14 d" else ""}>{r}</span>' for r in ['15 m', '1 h', '24 h', '14 d', '90 d'])
    tb = ''.join(f'<span{" class=on" if i == 0 else ""}>{t}</span>' for i, t in enumerate(TABS))
    dk = ''.join(f'<span{" class=on" if i == 0 else ""}>{d}</span>' for i, d in enumerate(DECK))
    return (f'  <div class="wordmark">BIRD<em>CAGE</em></div>\n  <div class="tabs">{tb}</div>\n'
            f'  <div class="status"><div class="ranges">{rng}</div>{STATUS[status]}<span class="who">tom (admin)</span></div>\n'
            f'  <div class="deck">{dk}</div>\n')


def page(title, css_extra, scenes):
    return (f'<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            f'<title>{title}</title>\n<style>{CSS}{css_extra}</style>\n</head>\n<body>\n\n' + '\n\n'.join(scenes) + '\n\n</body>\n</html>\n')


def scene(sid, aria, body, tag):
    return f'<section class="scene" id="{sid}" aria-label="{aria}">\n{body}  <div class="ibtn">i</div>\n  <div class="tag">{tag}</div>\n</section>'


def svg(parts):
    return '  <svg class="score" viewBox="0 0 1600 1000" aria-hidden="true">\n' + '\n'.join(p for p in parts if p) + '\n  </svg>\n'


QUIET_SUB = ('Nothing has touched a canary since <b>Thu 13 Aug</b> — one touch on canary-guest :23 from '
             '<span class="ip">198.51.100.200</span>, cleared with a note. The four canaries have phoned home every minute since; '
             'the newest heartbeat was three seconds ago.')
SILENT_SUB = ('Its last heartbeat was <b>21:58:19</b>, six minutes ago; it phones home every minute. A silent canary is not the quiet we '
              'want — the host may be down, or its firewall rule on the router may have moved. The other three are fine.')
NIGHT_SUB = ('<span class="ip">203.0.113.42</span> has reached <b>all four canaries in nine minutes</b> — ssh, then mysql, default passwords — '
             'and is still arriving. Three more visitors in the fortnight. Nothing here blocks: <b>lookback in mikroview ▸</b> to act.')

# ---------------------------------------------------------------- tiles and events
TILE_TOP, ROWS_TOP, ROW_H = 430, 604, 70


def tile(c, st, big, big_lab, acts='', cls=''):
    return (f'    <div class="tile k-{c} {cls}"><div class="n">canary-{c}<small>on {c}</small></div><div class="st">{st}</div>'
            f'<div class="pt">{ports[c]}</div><div class="big">{big}<small>{big_lab}</small></div>{acts}</div>\n')


def tiles(mode):
    out = f'  <div class="tiles" style="top:{TILE_TOP}px">\n'
    for c in lane:
        if mode == 'night':
            st = {'lan': '<span class="ok">● 9 s</span> · <span class="al">✱ swept 21:55</span><br>from inside 19:11',
                  'srv': '<span class="ok">● 41 s</span> · <span class="al">✱ swept 21:56</span><br>one touch yesterday',
                  'iot': '<span class="ok">● 22 s</span> · <span class="al">✱ swept 22:01</span> · <span class="rp">repeat :445</span>',
                  'guest': '<span class="ok">● 3 s</span> · <span class="al">✱ swept 22:04</span>'}[c]
            big = {'lan': '4', 'srv': '3', 'iot': '222', 'guest': '2'}[c]
            out += tile(c, st, big, 'hits · 14 d')
        elif mode == 'silent' and c == 'iot':
            out += tile(c, '<span class="off">○ silent 6 m 12 s</span> · last heard 21:58:19', '0', 'hits · 14 d',
                        '<div class="acts"><span class="pill">open canary-iot ▸</span><span class="pill quiet">mark as maintenance</span></div>', 'silent')
        else:
            out += tile(c, f'<span class="ok">● {beat_off[c]} s</span> · every minute · quiet 23 d', '0', 'hits · 14 d')
    return out + '  </div>\n'


EVENTS_NIGHT = [
    ('k-sw', '22:04:31<small>9 m · still arriving</small>', '✱ SWEEP<small>7× · 4 of 4</small>',
     '<span class="ip">203.0.113.42</span> walked <b>all four canaries</b> in nine minutes — ssh, then mysql, default passwords. Never seen before tonight.',
     '<span class="pill">lookback in mikroview ▸</span><span class="pill">raw lines ▸</span>'),
    ('k-rp', '21:59:10<small>6 nights · on schedule</small>', '✱ REPEAT<small>221× · 1 of 4</small>',
     '<span class="ip">198.51.100.7</span> knocks on <b>canary-iot :445</b> every ~20 minutes through the night, six nights running. Community-blocked since Tuesday.',
     '<span class="pill quiet">already blocked</span>'),
    ('k-in', '19:11:22<small>3 h ago</small>', '✱ FROM INSIDE<small>2× · 1 of 4</small>',
     '<span class="ip">10.0.40.23</span>, a guest device, browsed <b>canary-lan :80</b> and tried /admin. Never auto-blocked (#33).',
     '<span class="pill">which device? ▸</span>'),
    ('k-tc', 'yesterday<small>03:18:40</small>', '▲ ONE TOUCH<small>1× · 1 of 4</small>',
     '<span class="ip">192.0.2.88</span> logged in to <b>canary-srv :21</b> as anonymous, once, and left.',
     '<span class="pill quiet">clear with a note</span>'),
]
EVENTS_SILENT = [
    ('k-off', '21:58:19<small>6 m 12 s ago</small>', '○ DROPPED OUT<small>canary-iot</small>',
     '<b>canary-iot</b> stopped phoning home. Six heartbeats missed since. Not a visitor: the host may be down, or its firewall rule on the router may have moved.',
     '<span class="pill">open canary-iot ▸</span><span class="pill">lookback in mikroview ▸</span><span class="pill quiet">mark as maintenance</span>'),
]


def rows(events, top=ROWS_TOP):
    out = ''
    for i, (k, t, kd, who, acts) in enumerate(events):
        out += (f'  <div class="row {k}" style="top:{top+i*ROW_H}px"><div class="t">{t}</div><div class="kind">{kd}</div>'
                f'<div class="who">{who}</div><div class="acts">{acts}</div></div>\n')
    return out


def build(mode):
    day = NIGHT_DAY if mode == 'night' else QUIET_DAY
    parts = trace(hits=NIGHT_HITS if mode == 'night' else None, silent=(mode == 'silent')) + [axis(BAND[-1]+42, day)]
    body = chrome(mode) + svg(parts)
    if mode == 'night':
        body += '  <div class="grp" style="top:70px">the cage · fri 12 sep · <span class="r">1 flagged</span> · 232 hits today</div>\n'
        body += '  <div class="hero" style="top:94px"><b class="r">One address is walking the cage.</b></div>\n'
        body += f'  <div class="sub" style="top:134px">{NIGHT_SUB}</div>\n'
    else:
        body += '  <div class="grp" style="top:70px">the cage · sat 5 sep · 22:04:31</div>\n'
        if mode == 'silent':
            body += '  <div class="hero" style="top:94px">Quiet for <b class="ok">23 days</b> — but <b>canary-iot is silent.</b></div>\n'
            body += f'  <div class="sub" style="top:134px">{SILENT_SUB}</div>\n'
        else:
            body += '  <div class="hero" style="top:94px">Quiet for <b class="ok">23 days</b>.</div>\n'
            body += f'  <div class="sub" style="top:134px">{QUIET_SUB}</div>\n'
    body += tiles(mode)
    if mode == 'night':
        body += f'  <div class="grp" style="top:{ROWS_TOP-26}px">events · 14 days · <b>4 visitors</b> · newest first</div>\n' + rows(EVENTS_NIGHT)
        body += '  <div class="foot"><span>a quiet fortnight until <b>21:55</b> tonight — <span class="r">one address is walking the cage right now</span></span></div>\n'
    elif mode == 'silent':
        body += f'  <div class="grp" style="top:{ROWS_TOP+10}px">events · 14 days · <b>1</b> · no visitors</div>\n' + rows(EVENTS_SILENT, ROWS_TOP+36)
        body += '  <div class="foot"><span>twenty-three quiet days · <b>one canary has stopped talking</b> — silence is only good news while the heartbeat keeps coming</span></div>\n'
    else:
        body += f'  <div class="grp" style="top:{ROWS_TOP-26}px">events · 14 days · <b>none</b></div>\n'
        body += (f'  <div class="quiet-line" style="top:{ROWS_TOP-2}px">Nothing in the window. A flat trace is the cage working — '
                 'the only things moving on this page are the heartbeats.</div>\n')
        body += '  <div class="foot"><span>twenty-three quiet days · <span class="ok">all four phoning home</span> · nothing to act on</span></div>\n'
    body += f'  <div class="legend" style="top:912px">{LEGEND}</div>\n'
    return body


SCENES = [('quiet', 'a quiet fortnight: a flat trace, four canaries phoning home, no events', 'SCENE 1 · A QUIET FORTNIGHT'),
          ('silent', 'a canary gone silent: one line drops out of the trace', 'SCENE 2 · A CANARY GONE SILENT'),
          ('night', 'the sweep night: visitors rise from the trace, tiles and events beneath', 'SCENE 3 · THE SWEEP NIGHT')]

for letter, name, fname, css in [('l', 'The trace, outlined', 'direction-l-trace-outlined.html', L_CSS),
                                 ('m', 'The trace, outlined · silence in ink', 'direction-m-trace-outlined-ink.html', M_CSS)]:
    html = page(f'Birdcage · round 6 · {letter.upper()} · {name}', css,
                [scene(f'{letter}-{m}', f'{name}: {aria}', build(m), f'{letter.upper()} · {name.upper()} · {tag}') for m, aria, tag in SCENES])
    open(fname, 'w').write(html)
print('ok')
