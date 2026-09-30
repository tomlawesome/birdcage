#!/usr/bin/env python3
"""Round 7: the canary page (#115) -- one canary's own view, inside the ratified
shell (ADR-0004, round 6 M). The band, chrome, axis and data story are round 6's,
copied rather than imported so the round stands alone. Generates
direction-n-line-alone-prose.html and direction-o-line-alone-ledger.html.
Run here: python3 gen.py"""
from datetime import date, timedelta

# ---------------------------------------------------------------- data story (rounds 1-6)
NOW = 22*3600 + 4*60 + 31
QUIET_DAY, NIGHT_DAY = date(2026, 9, 5), date(2026, 9, 12)
lane = {'lan': 'var(--lan)', 'srv': 'var(--srv)', 'iot': 'var(--iot)', 'guest': 'var(--guest)'}
kind = {'sw': 'var(--sweep)', 'rp': 'var(--repeat)', 'in': 'var(--inside)', 'tc': 'var(--touch)'}
beat_off = {'lan': 9, 'srv': 41, 'iot': 22, 'guest': 3}
SILENT_LAST = 372
repeat = [321 + d*86400 + k*1200 for d in range(6) for k in range(37)][:221]
ports = {'iot': 'telnet 23 · ssh 22 · smb 445'}
C = 'iot'                      # the canary this page belongs to, in every scene
SELFTEST_AGO = NOW - 4*3600    # 04:00 today, and every day before it

NIGHT_HITS = [('sw', [164], 'root / toor', '203.0.113.42 → canary-iot · 22:01'),
              ('rp', repeat, '37 knocks tonight, every 20 min · six nights', '198.51.100.7 → canary-iot :445')]

# ---------------------------------------------------------------- axis (round 6, unchanged)
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


# ---------------------------------------------------------------- the line, alone
Y = 300     # the one line. At its own scale a rise may climb 60 px, not 34.


def beats(y, off, since=0):
    out, a = [], off
    while a < 900:
        if a >= since:
            out.append(f'<rect x="{cx(a)-.7:.1f}" y="{y-2}" width="1.4" height="4" fill="var(--ink-3)" opacity=".55"/>')
        a += 60
    return '\n'.join(out)


def clusters(agos, gap=6):
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
    a, b = x0 - w, min(x1 + w, X1)
    d = (f'M{a:.1f},{y} C{a+w*.55:.1f},{y} {x0-w*.45:.1f},{y-h} {x0:.1f},{y-h} '
         f'L{x1:.1f},{y-h} C{x1+(b-x1)*.45:.1f},{y-h} {b-(b-x1)*.55:.1f},{y} {b:.1f},{y}')
    return (f'<path d="{d}" fill="{col}" fill-opacity=".14" stroke="none"/>'
            f'<path d="{d}" fill="none" stroke="{col}" stroke-width="1.5" stroke-linejoin="round"/>')


def label(anchor, xx, y, col, l1, l2):
    return (f'<text x="{xx:.1f}" y="{y-16}" class="bl" text-anchor="{anchor}"><tspan fill="{col}">✱ </tspan>{l1}</text>'
            f'<text x="{xx:.1f}" y="{y-4}" class="bl dim" text-anchor="{anchor}">{l2}</text>')


def selftest_ticks(mode):
    """the canary's own self-tests: a hollow tick under the line at 04:00 each day.
    Ink, never colour: birdcage prodding its own canary is not a visitor."""
    out = []
    for k in range(14):
        ago = SELFTEST_AGO + k*86400
        x = cx(ago)
        failed = mode == 'failed' and k == 0
        if failed:
            out.append(f'<circle cx="{x:.1f}" cy="{Y+10}" r="3.4" fill="var(--ink)" stroke="var(--ink)" stroke-width="1.2"/>')
            out.append(f'<line x1="{x:.1f}" y1="{Y+6}" x2="{x:.1f}" y2="{Y-34}" stroke="var(--ink-3)" stroke-width="1"/>')
            out.append(f'<text x="{x:.1f}" y="{Y-52}" class="bl" text-anchor="middle">self-test 04:00 · <tspan fill="var(--ink)" font-weight="700">telnet did not answer</tspan></text>')
            out.append(f'<text x="{x:.1f}" y="{Y-40}" class="bl dim" text-anchor="middle">ssh, smb, portscan answered · next run 04:00 tomorrow</text>')
        else:
            out.append(f'<circle cx="{x:.1f}" cy="{Y+10}" r="2.8" fill="var(--void)" stroke="var(--ink-3)" stroke-width="1.1"/>')
    return '\n'.join(out)


def silences():
    """The two earlier silences this week, at the page's own scale: the same hollow mark, both labels
    to the left of their marks on two rows, so the failed self-test stem to the right clears them."""
    out = []
    for a0, lab, dy in [(4*86400 - 6*60, 'tue 1 sep · silent 11 min', -26), (2*86400 + NOW - (7*3600+12*60), 'thu 3 sep · silent 1 min', -12)]:
        x = cx(a0)
        out.append(f'<circle cx="{x:.1f}" cy="{Y}" r="3.2" fill="var(--void)" stroke="var(--ink-3)" stroke-width="1.2"/>')
        out.append(f'<text x="{x-8:.1f}" y="{Y+dy}" class="bl dim" text-anchor="end">{lab}</text>')
    return ''.join(out)


def line(mode):
    parts = []
    col = lane[C]
    if mode == 'silent':
        xs = cx(SILENT_LAST)
        yd = Y + 22
        parts.append(f'<line x1="{X0}" y1="{Y}" x2="{xs:.1f}" y2="{Y}" stroke="{col}" stroke-width="1.6" opacity=".7"/>')
        parts.append(f'<path d="M{xs:.1f},{Y} C{xs+10:.1f},{Y} {xs+8:.1f},{yd} {xs+20:.1f},{yd}" fill="none" stroke="var(--ink-3)" stroke-width="1.2"/>')
        parts.append(f'<line x1="{xs+20:.1f}" y1="{yd}" x2="{X1}" y2="{yd}" stroke="var(--ink-3)" stroke-width="1" stroke-dasharray="2 5" opacity=".8"/>')
        parts.append(beats(Y, beat_off[C], since=SILENT_LAST))
        parts.append(f'<circle cx="{xs:.1f}" cy="{Y}" r="3.8" fill="var(--void)" stroke="{col}" stroke-width="1.5"/>')
        parts.append(f'<text x="{xs-10:.1f}" y="{yd+3}" class="bl" text-anchor="end">dropped out · last heartbeat <tspan fill="var(--ink)">21:58:19</tspan> · silent 6 m 12 s</text>')
        # the two earlier silences this week, at the page's own scale, as the same mark
        parts.append(silences())
    else:
        parts.append(f'<line x1="{X0}" y1="{Y}" x2="{X1}" y2="{Y}" stroke="{col}" stroke-width="1.6" opacity=".7"/>')
        parts.append(beats(Y, beat_off[C]))
        if mode != 'night':
            parts.append(silences())
    parts.append(f'<text x="{X0-10}" y="{Y+3}" class="bandlab" fill="{col}" text-anchor="end">canary-{C}</text>')
    parts.append(selftest_ticks(mode))
    if mode == 'night':
        # rises at the page's own scale: taller, and the words have room
        placed = []
        for k, agos, l1, l2 in NIGHT_HITS:
            cl = clusters(agos)
            widest = max(range(len(cl)), key=lambda i: (cl[i][1]-cl[i][0], cl[i][2]))
            for i, (xa, xb, n) in enumerate(cl):
                if i != widest:
                    parts.append(bump(xa, xb, Y, 22, kind[k], 12))
                    continue
                h = 60 if k == 'sw' else 44
                bw = 14 + h*.2
                parts.append(bump(xa, xb, Y, h, kind[k], bw))
                anchor, ax = ('end', xa-bw-6) if (xa+xb)/2 > X1-300 else ('middle', (xa+xb)/2)
                parts.append(label(anchor, ax, Y-h, kind[k], l1, l2))
    top = Y - 110
    parts.append(f'<line x1="{X1}" y1="{top}" x2="{X1}" y2="{Y+40}" class="brink"/>')
    return parts


# ---------------------------------------------------------------- chrome (round 6, plus the page's crumb)
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
  .tabs .crumb { color: var(--ink-3); } .tabs .crumb b { color: var(--iot); font: 700 12px var(--mono); }
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
  .bandlab { font: 600 10.5px var(--mono); }
  .bl { font: 10.5px var(--mono); fill: var(--ink); } .bl.dim { fill: var(--ink-3); font-size: 9.5px; }

  .grp { position: absolute; left: 54px; font: 600 9.5px var(--mono); letter-spacing: .16em; color: var(--ink-3); text-transform: uppercase; }
  .grp b { color: var(--ink-2); font-weight: 600; } .grp .r { color: var(--alarm); } .grp .c { color: var(--iot); }
  .hero { position: absolute; left: 54px; font: 500 26px/1.2 var(--sans); color: var(--ink); letter-spacing: -.01em; }
  .hero b { font-weight: 700; } .hero .ok { color: var(--ok); } .hero .r { color: var(--alarm); } .hero .c { color: var(--iot); }
  .sub { position: absolute; left: 54px; width: 900px; font: 13px/1.55 var(--sans); color: var(--ink-2); }
  .sub b { color: var(--ink); font-weight: 600; } .sub .ip { font: 12.5px var(--mono); color: var(--ink); }
  .acts { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
  .pill { font: 600 11px var(--sans); color: var(--accent); border: 1px solid var(--hair-2); border-radius: 999px; padding: 3px 12px; white-space: nowrap; }
  .pill.quiet { color: var(--ink-3); }

  /* the page's lower half */
  .col { position: absolute; }
  .col h3 { margin: 0 0 10px; font: 600 9.5px var(--mono); letter-spacing: .16em; color: var(--ink-3); text-transform: uppercase; }
  .col h3 b { color: var(--ink-2); font-weight: 600; } .col h3 .ok { color: var(--ok); } .col h3 .r { color: var(--ink); }
  .facts { display: grid; grid-template-columns: 110px 1fr; row-gap: 6px; column-gap: 12px; font: 11.5px var(--mono); color: var(--ink); }
  .facts span:nth-child(odd) { color: var(--ink-3); }
  .facts .c { color: var(--iot); }
  .legend { position: absolute; left: 54px; right: 80px; font: 11px var(--sans); color: var(--ink-3); display: flex; gap: 22px; flex-wrap: wrap; }
  .legend i { display: inline-block; width: 8px; height: 8px; border-radius: 50%; vertical-align: -1px; margin-right: 5px; }
  .legend .ln { display: inline-block; width: 22px; height: 0; border-top: 1.5px solid var(--iot); vertical-align: 3px; margin-right: 6px; opacity: .7; }
  .legend .gap { display: inline-block; width: 22px; height: 0; border-top: 1.5px dashed var(--ink-3); vertical-align: 3px; margin-right: 6px; }
  .legend .tick { display: inline-block; width: 6px; height: 6px; border-radius: 50%; border: 1px solid var(--ink-3); vertical-align: -1px; margin-right: 6px; }
  .legend .nw { color: var(--now); }
  .foot { position: absolute; left: 0; right: 40px; bottom: 14px; display: flex; justify-content: center; gap: 60px; font: 12.5px var(--sans); color: var(--ink-2); }
  .foot b { color: var(--ink); font-weight: 600; } .foot .r { color: var(--alarm); } .foot .ok { color: var(--ok); font-weight: 600; }
  @media (prefers-reduced-motion: no-preference) { .status .dot { animation: pulse 1.8s ease-in-out infinite; } .status .dot.off { animation: none; } @keyframes pulse { 50% { opacity: .4; } } }
"""
# N: the self-test and the history are sentences, one per line.
N_CSS = """
  .st-lines { font: 12px/1.7 var(--mono); color: var(--ink-2); }
  .st-lines div { display: grid; grid-template-columns: 110px 1fr; column-gap: 12px; }
  .st-lines .svc { color: var(--ink); }
  .st-lines .ok { color: var(--ok); } .st-lines .no { color: var(--ink); font-weight: 700; } .st-lines .un { color: var(--ink-3); }
  .st-lines .g { color: var(--ink-3); }
  .st-note { margin-top: 10px; font: italic 12px/1.5 var(--sans); color: var(--ink-3); max-width: 110ch; }
  .hist { font: 12.5px/1.5 var(--sans); color: var(--ink-2); }
  .hist p { margin: 0 0 8px; padding-left: 112px; position: relative; }
  .hist p .t { position: absolute; left: 0; top: 1px; font: 11px var(--mono); color: var(--ink-3); }
  .hist p b { color: var(--ink); font-weight: 600; } .hist .ok { color: var(--ok); } .hist .live { color: var(--ink); font-weight: 700; }
  .hist .more { color: var(--ink-3); font-style: italic; padding-left: 112px; }
"""
# O: the self-test is a strip of service boxes; the history is a thread.
O_CSS = """
  .strip { display: flex; gap: 12px; }
  .svc { --b: var(--ok); width: 176px; padding: 10px 12px 9px; border: 1px solid var(--b); border-radius: 8px; background: var(--raised); }
  .svc .n { font: 700 12px var(--mono); color: var(--ink); } .svc .n small { color: var(--ink-3); font-weight: 500; margin-left: 6px; }
  .svc .r { margin-top: 4px; font: 11px var(--mono); color: var(--b); }
  .svc .g { margin-top: 6px; font: 600 9px var(--mono); letter-spacing: .14em; text-transform: uppercase; color: var(--ink-3); }
  .svc.no { --b: var(--ink); background: transparent; } .svc.no .r { font-weight: 700; }
  .svc.un { --b: var(--ink-3); border-style: dashed; background: transparent; } .svc.un .r { color: var(--ink-3); }
  .strip-note { margin-top: 10px; font: italic 12px/1.5 var(--sans); color: var(--ink-3); }
  .thread { position: relative; padding-left: 26px; }
  .thread::before { content: ''; position: absolute; left: 6px; top: 6px; bottom: 6px; width: 0; border-left: 1px solid var(--hair-2); }
  .thread .ev { position: relative; margin: 0 0 9px; font: 12.5px/1.45 var(--sans); color: var(--ink-2); }
  .thread .ev::before { content: ''; position: absolute; left: -24px; top: 6px; width: 7px; height: 7px; border-radius: 50%; background: var(--void); border: 1.4px solid var(--ink-3); }
  .thread .ev.ok::before { border-color: var(--ok); background: var(--ok); }
  .thread .ev.fault::before { border-color: var(--ink); background: var(--ink); }
  .thread .ev.live::before { border-color: var(--ink); background: var(--void); border-width: 2px; }
  .thread .ev .t { font: 11px var(--mono); color: var(--ink-3); display: inline-block; width: 120px; }
  .thread .ev b { color: var(--ink); font-weight: 600; } .thread .ev .dur { color: var(--ink-3); font: 11px var(--mono); }
  .thread .more { color: var(--ink-3); font-style: italic; font-size: 12px; }
"""

STATUS = {
    'quiet': '<span><span class="dot"></span>QUIET · 4 of 4 phoning home</span><span>◎ 0 visitors · 14 d</span>',
    'failed': '<span><span class="dot"></span>4 of 4 phoning home · <span class="mute">canary-iot failed its self-test</span></span><span>◎ 0 visitors · 14 d</span>',
    'silent': '<span><span class="dot off"></span>3 of 4 phoning home · <span class="mute">canary-iot silent 6 m</span></span><span>◎ 0 visitors · 14 d</span>',
    'night': '<span><span class="dot"></span>LIVE · 4 canaries</span><span class="flag">⚑ <b>1</b></span><span>◎ 4 visitors</span>',
}
DECK = ['THE TRACE', 'VISITORS', 'AUDIT LOG', 'SETTINGS']
LEGEND = ('<span><span class="ln"></span>the line is this canary\'s heartbeat, unbroken</span><span><span class="gap"></span>a drop is silence</span>'
          '<span><span class="tick"></span>a hollow tick under the line is birdcage testing its own canary, 04:00 daily</span>'
          '<span>a rise is a visitor: <i style="background:var(--sweep)"></i>sweep <i style="background:var(--repeat)"></i>repeat '
          '<i style="background:var(--inside)"></i>from inside <i style="background:var(--touch)"></i>one touch</span><span class="nw">— the brink · now</span>')


def chrome(status):
    rng = ''.join(f'<span{" class=on" if r == "14 d" else ""}>{r}</span>' for r in ['15 m', '1 h', '24 h', '14 d', '90 d'])
    tb = '<span>the cage</span><span class="crumb">› <b>canary-iot</b></span><span>visitors</span><span>audit log</span>'
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


# ---------------------------------------------------------------- words
HERO = {
    'quiet': ('<span class="c">canary-iot</span> is quiet, and <b class="ok">answers when tested</b>.',
              'Nothing has touched it since it was enrolled on <b>Wed 12 Aug</b>. It phones home every minute — the last heartbeat was 22 seconds ago — '
              'and this morning\'s self-test at <b>04:00</b> reached all four of its services. Two short silences this week, both over in minutes.'),
    'failed': ('<span class="c">canary-iot</span> is phoning home — but <b>deaf on telnet.</b>',
               'This morning\'s self-test at <b>04:00</b> reached ssh, smb and the portscan lure; <b>telnet :23 did not answer</b>. The agent is fine and the box is up, '
               'so a visitor on that port would go unseen. Run the test again after looking at the box; the next scheduled run is 04:00 tomorrow.'),
    'silent': ('<span class="c">canary-iot</span> is silent — <b>the third time this week.</b>',
               'Its last heartbeat was <b>21:58:19</b>, six minutes ago. It also dropped out on <b>Tue 1 Sep</b> for eleven minutes and on <b>Thu 3 Sep</b> for one, '
               'and came back on its own both times. Three silences in five days is not a bad minute: the host, or its rule on the router, wants looking at.'),
    'night': ('<span class="c">canary-iot</span> was <b class="r">swept at 22:01</b>, and is still being knocked on.',
              '<span class="ip">203.0.113.42</span> tried <b>root / toor</b> on ssh at 22:01 — the same address that walked all four canaries tonight. '
              'Underneath it, <span class="ip">198.51.100.7</span> has knocked on :445 every twenty minutes for six nights; community-blocked since Tuesday. Nothing here blocks: <b>lookback in mikroview ▸</b> to act.'),
}
GRP = {'quiet': 'the cage › <span class="c">canary-iot</span> · sat 5 sep · 22:04:31', 'failed': 'the cage › <span class="c">canary-iot</span> · sat 5 sep · <b>self-test failed</b>',
       'silent': 'the cage › <span class="c">canary-iot</span> · sat 5 sep · <b>silent 6 m 12 s</b>', 'night': 'the cage › <span class="c">canary-iot</span> · fri 12 sep · <span class="r">1 flagged</span> · 222 hits today'}

ACTS = {
    'quiet': '<span class="pill">run the self-test now ▸</span><span class="pill quiet">mark as maintenance</span>',
    'failed': '<span class="pill">run the self-test now ▸</span><span class="pill">lookback in mikroview ▸</span><span class="pill quiet">mark as maintenance</span>',
    'silent': '<span class="pill">lookback in mikroview ▸</span><span class="pill quiet">mark as maintenance</span>',
    'night': '<span class="pill">lookback in mikroview ▸</span><span class="pill">raw lines ▸</span><span class="pill quiet">run the self-test now</span>',
}

# per-service result of the last self-test: (service, port, answered?, grade)  grade None = untested
SELFTEST = {
    'quiet': [('ssh', '22', True, 'marked'), ('telnet', '23', True, 'marked'), ('smb', '445', True, 'marked'), ('portscan', '', True, 'attributed'), ('ntp', '123', None, None)],
    'failed': [('ssh', '22', True, 'marked'), ('telnet', '23', False, None), ('smb', '445', True, 'marked'), ('portscan', '', True, 'attributed'), ('ntp', '123', None, None)],
}
SELFTEST['silent'] = SELFTEST['quiet']
SELFTEST['night'] = SELFTEST['quiet']
ST_HEAD = {'quiet': 'self-test · today 04:00:07 · <span class="ok">passed</span> · 4 of 4',
           'failed': 'self-test · today 04:00:07 · <span class="r">failed</span> · 3 of 4',
           'silent': 'self-test · today 04:00:07 · <span class="ok">passed</span> · 4 of 4 · <b>no run since it went silent</b>',
           'night': 'self-test · today 04:00:07 · <span class="ok">passed</span> · 4 of 4'}
GRADE_WORDS = {'marked': 'the probe\'s marker came back in the event',
               'challenge-marked': 'the marker was a signed answer to a challenge',
               'attributed': 'no marker can travel; the agent claimed its own probe and birdcage matched the claim'}
ST_NOTE = ('Three grades of proof, all a pass: <b>marked</b> — the probe\'s marker came back in the event; <b>challenge-marked</b> — the marker was a signed answer to a challenge (vnc); '
           '<b>attributed</b> — no marker can travel, so the agent claims its own probe as it leaves and birdcage matches the claim. Untested is not a fault: the service is off on this canary.')

# the state history, newest first: (when, state, text, cls)
HIST = {
    'quiet': [('today 04:00', 'self-test passed', 'four of four services answered — ssh, telnet and smb marked, portscan attributed', 'ok'),
              ('thu 3 sep 07:12', 'silent · 1 min', 'one heartbeat missed, back at 07:13 on its own', 'fault'),
              ('tue 1 sep 21:58', 'silent · 11 min', 'eleven heartbeats missed, back at 22:09 on its own', 'fault'),
              ('thu 13 aug', 'quiet', 'the last thing that touched the cage was on canary-guest, not here', 'ok'),
              ('wed 12 aug 09:45', 'registered', 'first self-test passed 3 min 50 s after enrolment; pending until then', 'ok'),
              ('wed 12 aug 09:41', 'enrolled', 'by tom, on iot, mockingbird 0.4.1 — pending its first self-test', 'pend')],
    'failed': [('today 04:00', 'self-test failed · 18 h', 'telnet :23 did not answer; ssh, smb and portscan did. <span class="live">still failing</span> — no run since', 'live'),
               ('thu 3 sep 07:12', 'silent · 1 min', 'one heartbeat missed, back at 07:13 on its own', 'fault'),
               ('tue 1 sep 21:58', 'silent · 11 min', 'eleven heartbeats missed, back at 22:09 on its own', 'fault'),
               ('wed 12 aug 09:45', 'registered', 'first self-test passed 3 min 50 s after enrolment', 'ok'),
               ('wed 12 aug 09:41', 'enrolled', 'by tom, on iot, mockingbird 0.4.1', 'pend')],
    'silent': [('today 21:58', 'silent · 6 min 12 s', 'six heartbeats missed so far. <span class="live">still silent</span>', 'live'),
               ('today 04:00', 'self-test passed', 'four of four services answered', 'ok'),
               ('thu 3 sep 07:12', 'silent · 1 min', 'one heartbeat missed, back at 07:13 on its own', 'fault'),
               ('tue 1 sep 21:58', 'silent · 11 min', 'eleven heartbeats missed, back at 22:09 on its own', 'fault'),
               ('wed 12 aug 09:45', 'registered', 'first self-test passed 3 min 50 s after enrolment', 'ok'),
               ('wed 12 aug 09:41', 'enrolled', 'by tom, on iot, mockingbird 0.4.1', 'pend')],
    'night': [('today 22:01', 'swept', '<span class="ip">203.0.113.42</span> tried root / toor on ssh — part of a walk across all four canaries', 'fault'),
              ('today 04:00', 'self-test passed', 'four of four services answered', 'ok'),
              ('six nights', 'repeat visitor', '<span class="ip">198.51.100.7</span> knocks on :445 every ~20 min, 221 times; community-blocked since Tuesday', 'fault'),
              ('thu 3 sep 07:12', 'silent · 1 min', 'one heartbeat missed, back on its own', 'fault'),
              ('tue 1 sep 21:58', 'silent · 11 min', 'eleven heartbeats missed, back on its own', 'fault'),
              ('wed 12 aug 09:41', 'enrolled', 'by tom, on iot, mockingbird 0.4.1 — registered 3 min 50 s later', 'ok')],
}
FACTS = [('kind', 'honeypot'), ('lane', '<span class="c">iot</span> · 10.0.30.0/24'), ('address', '10.0.30.9'), ('listening', ports['iot']),
         ('lure only', 'portscan · ntp off'), ('heartbeat', 'every minute'), ('self-test', 'daily · 04:00'), ('enrolled', 'wed 12 aug 09:41 · by tom'),
         ('agent', 'mockingbird 0.4.1 · current'), ]

LOWER = 420     # where the page's lower half starts


def facts_col(mode, left, width):
    tok = ('token', 'rotated thu 10 sep · next in 25 h' if mode == 'night' else 'rotated thu 3 sep · next in 25 h')
    f = ''.join(f'<span>{k}</span><span>{v}</span>' for k, v in FACTS + [tok])
    return (f'  <div class="col" style="top:{LOWER}px;left:{left}px;width:{width}px"><h3>this canary</h3><div class="facts">{f}</div>'
            f'<div class="acts" style="margin-top:16px">{ACTS[mode]}</div></div>\n')


def n_lower(mode):
    st = ''
    for svc, port, ok, grade in SELFTEST[mode]:
        name = f'<span class="svc">{svc}' + (f' <span class="g">:{port}</span>' if port else '') + '</span>'
        if ok is None:
            st += f'<div>{name}<span class="un">untested · off on this canary</span></div>'
        elif ok:
            st += f'<div>{name}<span><span class="ok">answered</span> <span class="g">· {grade}</span></span></div>'
        else:
            st += f'<div>{name}<span class="no">did not answer</span></div>'
    out = f'  <div class="col" style="top:{LOWER}px;left:54px;width:820px"><h3>{ST_HEAD[mode]}</h3><div class="st-lines">{st}</div><div class="st-note">{ST_NOTE}</div></div>\n'
    h = ''.join(f'<p><span class="t">{t}</span><b>{s}</b> — {x}</p>' for t, s, x, _ in HIST[mode])
    out += f'  <div class="col hist" style="top:{LOWER+222}px;left:54px;width:840px"><h3>history · every state this canary has been in · newest first</h3>{h}<div class="more">enrolled {31 if mode == "night" else 24} days ago · nothing earlier</div></div>\n'
    out += facts_col(mode, 960, 520)
    return out


def o_lower(mode):
    boxes = ''
    for svc, port, ok, grade in SELFTEST[mode]:
        name = f'<div class="n">{svc}' + (f'<small>:{port}</small>' if port else '') + '</div>'
        if ok is None:
            boxes += f'<div class="svc un">{name}<div class="r">untested</div><div class="g">off on this canary</div></div>'
        elif ok:
            boxes += f'<div class="svc">{name}<div class="r">● answered</div><div class="g">{grade}</div></div>'
        else:
            boxes += f'<div class="svc no">{name}<div class="r">○ did not answer</div><div class="g">no proof</div></div>'
    out = f'  <div class="col" style="top:{LOWER}px;left:54px;width:1000px"><h3>{ST_HEAD[mode]}</h3><div class="strip">{boxes}</div><div class="strip-note">{ST_NOTE}</div></div>\n'
    h = ''
    for t, s, x, cls in HIST[mode]:
        h += f'<div class="ev {cls}"><span class="t">{t}</span><b>{s}</b> — {x}</div>'
    out += f'  <div class="col" style="top:{LOWER+190}px;left:54px;width:860px"><h3>history · every state this canary has been in · newest first</h3><div class="thread">{h}<div class="more">enrolled {31 if mode == "night" else 24} days ago · nothing earlier</div></div></div>\n'
    out += facts_col(mode, 1100, 400)
    return out


def build(mode, lower):
    day = NIGHT_DAY if mode == 'night' else QUIET_DAY
    parts = line(mode) + [axis(Y+42, day)]
    body = chrome(mode) + svg(parts)
    hero, sub = HERO[mode]
    body += f'  <div class="grp" style="top:70px">{GRP[mode]}</div>\n'
    body += f'  <div class="hero" style="top:94px">{hero}</div>\n'
    body += f'  <div class="sub" style="top:134px">{sub}</div>\n'
    body += lower(mode)
    foot = {'quiet': '<span>twenty-four days on the iot lane · <span class="ok">answers when tested</span> · nothing to act on</span>',
            'failed': '<span>phoning home, delivering, <b>deaf on one port</b> — a canary that cannot hear a visitor is no canary on that port</span>',
            'silent': '<span><b>three silences in five days</b> — silence is only good news while the heartbeat keeps coming</span>',
            'night': '<span>a quiet three weeks until <b>22:01</b> tonight — <span class="r">the address walking the cage reached this one too</span></span>'}[mode]
    body += f'  <div class="foot">{foot}</div>\n'
    body += f'  <div class="legend" style="top:912px">{LEGEND}</div>\n'
    return body


SCENES = [('quiet', 'canary-iot, quiet and answering its self-test', 'SCENE 1 · QUIET, AND ANSWERS WHEN TESTED'),
          ('failed', 'canary-iot failed this morning\'s self-test on telnet', 'SCENE 2 · DEAF ON TELNET'),
          ('silent', 'canary-iot gone silent for the third time this week', 'SCENE 3 · SILENT, THIRD TIME THIS WEEK'),
          ('night', 'canary-iot on the sweep night, at its own scale', 'SCENE 4 · THE SWEEP NIGHT, FROM THIS CANARY')]

for letter, name, fname, css, lower in [('n', 'The line, alone · prose', 'direction-n-line-alone-prose.html', N_CSS, n_lower),
                                        ('o', 'The line, alone · ledger', 'direction-o-line-alone-ledger.html', O_CSS, o_lower)]:
    html = page(f'Birdcage · round 7 · {letter.upper()} · {name}', css,
                [scene(f'{letter}-{m}', f'{name}: {aria}', build(m, lower), f'{letter.upper()} · {name.upper()} · {tag}') for m, aria, tag in SCENES])
    open(fname, 'w').write(html)
print('ok')
