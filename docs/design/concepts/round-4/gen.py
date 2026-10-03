#!/usr/bin/env python3
"""Round 4: the score re-centred on the quiet state. Generates
direction-h-quiet-score.html and direction-i-pulse.html in full.
Run from this directory: python3 gen.py"""
from datetime import date, timedelta

# ---------------------------------------------------------------- data story
NOW = 22*3600 + 4*60 + 31          # 22:04:31 on every scene
QUIET_DAY = date(2026, 9, 5)        # scenes 1–2: a quiet Saturday, three weeks after the last visitor
NIGHT_DAY = date(2026, 9, 12)       # scene 3: the sweep night from rounds 1–3
lane = {'lan': 'var(--lan)', 'srv': 'var(--srv)', 'iot': 'var(--iot)', 'guest': 'var(--guest)'}
kind = {'sw': 'var(--sweep)', 'rp': 'var(--repeat)', 'in': 'var(--inside)', 'tc': 'var(--touch)'}
beat_off = {'lan': 9, 'srv': 41, 'iot': 22, 'guest': 3}
SILENT_LAST = 372                    # canary-iot's last heartbeat, 21:58:19, in scene 2
sweep = [(0, 'guest', 'root / 123456'), (29, 'guest', 'admin / admin'), (164, 'iot', 'root / toor'),
         (429, 'srv', 'mysql root / (empty)'), (453, 'srv', 'root / password'), (531, 'lan', 'root / root'),
         (532, 'lan', 'session · libssh2')]
repeat = [(321 + d*86400 + k*1200, 'iot') for d in range(6) for k in range(37)][:221]
inside = [(10389, 'lan'), (10407, 'lan')]
touch = [(153951, 'srv')]
hits_by = {'guest': [(0, 'sw'), (29, 'sw')], 'iot': [(164, 'sw')] + [(a, 'rp') for a, _ in repeat],
           'srv': [(429, 'sw'), (453, 'sw'), (153951, 'tc')], 'lan': [(531, 'sw'), (532, 'sw'), (10389, 'in'), (10407, 'in')]}

# ---------------------------------------------------------------- axis
SEGS = [(0, 900, 300), (900, 3600, 180), (3600, 86400, 200), (86400, 1209600, 200)]  # ago range, share of 880


def axis_fn(X0, X1):
    scale = (X1-X0)/880
    def cx(ago):
        x = X1
        for a0, a1, w in SEGS:
            if ago <= a1:
                return x - (ago-a0)/(a1-a0)*w*scale
            x -= w*scale
        return X0
    return cx


def tick(x, y, h, col, op=1, w=2.2):
    return f'<line x1="{x:.1f}" y1="{y-h/2}" x2="{x:.1f}" y2="{y+h/2}" stroke="{col}" stroke-width="{w}" stroke-linecap="round" opacity="{op}"/>'


def axis(X0, X1, cx, y, day, stretched_caption=True):
    out = []
    for lab, ago in [('14 d', 1209600), ('24 h', 86400), ('1 h', 3600), ('15 m', 900)]:
        x = cx(ago)
        out.append(f'<text x="{x:.1f}" y="{y}" class="ax">{lab}</text><line x1="{x:.1f}" y1="{y+6}" x2="{x:.1f}" y2="{y+14}" class="axt"/>')
    out.append(f'<text x="{X1}" y="{y}" class="ax now" text-anchor="end">NOW · 22:04:31</text>')
    # midnights across the fortnight, three of them named
    for k in range(14):
        ago = NOW + k*86400
        x = cx(ago)
        out.append(f'<line x1="{x:.1f}" y1="{y+9}" x2="{x:.1f}" y2="{y+14}" class="axt" opacity=".6"/>')
        if k in (4, 8, 12):
            d = day - timedelta(days=k)
            out.append(f'<text x="{x:.1f}" y="{y+26}" class="axs">{d.strftime("%a %-d %b").lower()}</text>')
    out.append(f'<text x="{(cx(86400)+cx(3600))/2:.1f}" y="{y+26}" class="axs">23 hours, compressed</text>')
    if stretched_caption:
        out.append(f'<text x="{(cx(900)+X1)/2:.1f}" y="{y+26}" class="axs">the last quarter hour, stretched</text>')
    return '\n'.join(out)


def brink(X1, y0, y1):
    return f'<line x1="{X1}" y1="{y0}" x2="{X1}" y2="{y1}" class="brink"/>'


def beats(cx, y, off, since=0):
    """dim heartbeat marks where the axis is stretched; `since` hides beats newer than that"""
    out, a = [], off
    while a < 900:
        if a >= since:
            out.append(f'<rect x="{cx(a)-.8:.1f}" y="{y-2.5}" width="1.6" height="5" fill="var(--ink-3)" opacity=".55"/>')
        a += 60
    return '\n'.join(out)


def canary_stave(X0, X1, cx, y, c, hits=(), silent_since=None):
    """the line is the heartbeat, unbroken; a break is silence"""
    out = []
    if silent_since is None:
        out.append(f'<line x1="{X0}" y1="{y}" x2="{X1}" y2="{y}" stroke="{lane[c]}" stroke-width="1.2" opacity=".5"/>')
        out.append(beats(cx, y, beat_off[c]))
    else:
        xs = cx(silent_since)
        out.append(f'<line x1="{X0}" y1="{y}" x2="{xs:.1f}" y2="{y}" stroke="{lane[c]}" stroke-width="1.2" opacity=".5"/>')
        out.append(f'<line x1="{xs:.1f}" y1="{y}" x2="{X1}" y2="{y}" stroke="var(--ink-3)" stroke-width="1" stroke-dasharray="2 5" opacity=".7"/>')
        out.append(beats(cx, y, beat_off[c], since=silent_since))
        out.append(f'<circle cx="{xs:.1f}" cy="{y}" r="4" fill="var(--void)" stroke="{lane[c]}" stroke-width="1.4"/>')
        out.append(f'<text x="{xs-9:.1f}" y="{y-11}" class="lyric" text-anchor="end">last heartbeat 21:58:19 · silent 6 m 12 s</text>')
    for ago, k in hits:
        out.append(tick(cx(ago), y, 12, kind[k], .55 if k == 'rp' else 1, 1.6 if k == 'rp' else 2.2))
    return '\n'.join(out)


def visitor_stave(X0, X1, cx, y, ticks):
    dense = len(ticks) > 50
    out = [f'<line x1="{X0}" y1="{y}" x2="{X1}" y2="{y}" class="stv"/>']
    for a, c, *_ in ticks:
        out.append(tick(cx(a), y, 14, lane[c], .55 if dense else 1, 1.6 if dense else 2.2))
    return '\n'.join(out)


def flag(cx, y0, y1, ylab, ago=532, label='✱ 21:55 · sweep born'):
    x = cx(ago)
    return f'<line x1="{x:.1f}" y1="{y0}" x2="{x:.1f}" y2="{y1}" class="flagline"/><text x="{x-6:.1f}" y="{ylab}" class="flag-t" text-anchor="end">{label}</text>'


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
  .stv { stroke: var(--hair-2); stroke-width: 1; }
  .ax { font: 600 9.5px var(--mono); letter-spacing: .12em; fill: var(--ink-3); text-transform: uppercase; }
  .ax.now { fill: var(--now); letter-spacing: .06em; }
  .axs { font: 9px var(--sans); fill: var(--ink-3); text-anchor: middle; opacity: .8; }
  .axt { stroke: var(--hair-2); }
  .brink { stroke: var(--now); stroke-width: 1.6; }
  .flagline { stroke: var(--alarm); stroke-width: .7; stroke-dasharray: 2 5; opacity: .7; }
  .flag-t { font: 700 9.5px var(--mono); fill: var(--alarm); }
  .lanelab { font: 600 10px var(--mono); }
  .lanelab tspan { font-weight: 500; fill: var(--ink-3); } .lanelab .ok { fill: var(--ok); } .lanelab .al { fill: var(--alarm); font-weight: 700; } .lanelab .rp { fill: var(--repeat); font-weight: 700; }
  .lyric { font: 10.5px var(--mono); fill: var(--ink-2); } .lyric.dim { fill: var(--ink-3); }

  /* the sentence at the top of the cage */
  .grp { position: absolute; left: 54px; font: 600 9.5px var(--mono); letter-spacing: .16em; color: var(--ink-3); text-transform: uppercase; }
  .grp b { color: var(--ink-2); font-weight: 600; } .grp .r { color: var(--alarm); }
  .hero { position: absolute; left: 54px; font: 500 26px/1.2 var(--sans); color: var(--ink); letter-spacing: -.01em; }
  .hero b { font-weight: 700; } .hero .ok { color: var(--ok); } .hero .r { color: var(--alarm); }
  .sub { position: absolute; left: 54px; font: 13px/1.55 var(--sans); color: var(--ink-2); }
  .sub b { color: var(--ink); font-weight: 600; } .sub .ip { font: 12.5px var(--mono); color: var(--ink); }
  .quiet-line { position: absolute; left: 54px; font: italic 13px/1.5 var(--sans); color: var(--ink-3); }
  .quiet-line b { color: var(--ink-2); font-weight: 600; font-style: normal; }
  .acts { position: absolute; left: 54px; display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
  .pill { font: 600 11px var(--sans); color: var(--accent); border: 1px solid var(--hair-2); border-radius: 999px; padding: 4px 14px; white-space: nowrap; }
  .pill.quiet { color: var(--ink-3); } .pill.warn { color: var(--now); border-color: rgba(232,176,90,.5); }
  .acts .why { font: 10px var(--mono); color: var(--ink-3); }

  /* birds, left of a canary's stave */
  .bird { position: absolute; left: 54px; width: 566px; display: grid; grid-template-columns: 120px 1fr; column-gap: 14px; align-items: baseline; }
  .bird .n { font: 650 11.5px var(--mono); } .bird .s { font: 11px var(--mono); color: var(--ink-3); }
  .bird .s .beat { color: var(--ok); } .bird .s .swept { color: var(--alarm); font-weight: 700; } .bird .s .rep { color: var(--repeat); font-weight: 700; }
  .bird .s .off { color: var(--ink); font-weight: 700; }

  /* visitor rows, the docket, left of a visitor's stave */
  .row { position: absolute; left: 40px; width: 580px; height: 84px; display: grid; grid-template-columns: 120px 1fr 44px; column-gap: 14px; align-items: center; padding-left: 14px; border-bottom: 1px solid var(--hair); }
  .row::before { content: ''; position: absolute; left: 0; top: 10px; bottom: 10px; width: 3px; border-radius: 2px; background: var(--k); }
  .row.k-sw { --k: var(--sweep); } .row.k-rp { --k: var(--repeat); } .row.k-in { --k: var(--inside); } .row.k-tc { --k: var(--touch); }
  .row .kind { font: 700 11px var(--mono); letter-spacing: .06em; color: var(--k); white-space: nowrap; }
  .row .kind small { display: block; font: 10px var(--mono); color: var(--ink-3); letter-spacing: 0; margin-top: 3px; font-weight: 500; }
  .row .who { font: 12.5px var(--sans); color: var(--ink-2); line-height: 1.45; }
  .row .who .ip { font: 12.5px var(--mono); color: var(--ink); } .row .who b { color: var(--ink); font-weight: 600; }
  .row .n { text-align: right; font: 12px var(--mono); color: var(--ink); } .row .n small { display: block; font: 10px var(--mono); color: var(--ink-3); }

  /* visitor chips, the pulse's whole docket */
  .chips { position: absolute; left: 140px; right: 80px; display: flex; gap: 10px; align-items: center; flex-wrap: wrap; font: 11px var(--mono); color: var(--ink-3); }
  .chip { --k: var(--ink-3); border: 1px solid var(--hair-2); border-left: 3px solid var(--k); border-radius: 4px; padding: 5px 12px 5px 10px; font: 11px var(--mono); color: var(--ink-2); }
  .chip b { color: var(--k); font-weight: 700; } .chip .ip { color: var(--ink); }
  .chip.k-sw { --k: var(--sweep); } .chip.k-rp { --k: var(--repeat); } .chip.k-in { --k: var(--inside); } .chip.k-tc { --k: var(--touch); }

  .legend { position: absolute; left: 54px; right: 80px; font: 11px var(--sans); color: var(--ink-3); display: flex; gap: 22px; flex-wrap: wrap; }
  .legend i { display: inline-block; width: 8px; height: 8px; border-radius: 50%; vertical-align: -1px; margin-right: 5px; }
  .legend .ln { display: inline-block; width: 22px; height: 0; border-top: 1.5px solid var(--lan); vertical-align: 3px; margin-right: 6px; opacity: .7; }
  .legend .gap { display: inline-block; width: 22px; height: 0; border-top: 1.5px dashed var(--ink-3); vertical-align: 3px; margin-right: 6px; }
  .legend .nw { color: var(--now); }
  .foot { position: absolute; left: 0; right: 40px; bottom: 14px; display: flex; justify-content: center; gap: 60px; font: 12.5px var(--sans); color: var(--ink-2); }
  .foot b { color: var(--ink); font-weight: 600; } .foot .r { color: var(--alarm); } .foot .ok { color: var(--ok); font-weight: 600; }
  @media (prefers-reduced-motion: no-preference) { .status .dot { animation: pulse 1.8s ease-in-out infinite; } .status .dot.off { animation: none; } @keyframes pulse { 50% { opacity: .4; } } }
"""

STATUS = {
    'quiet': '<span><span class="dot"></span>QUIET · 4 of 4 phoning home</span><span>◎ 0 visitors · 14 d</span>',
    'silent': '<span><span class="dot off"></span>3 of 4 phoning home · <span class="mute">canary-iot silent 6 m</span></span><span>◎ 0 visitors · 14 d</span>',
    'night': '<span><span class="dot"></span>LIVE · 4 canaries</span><span class="flag">⚑ <b>1</b></span><span>◎ 4 visitors</span>',
}


def chrome(status, deck, tabs):
    rng = ''.join(f'<span{" class=on" if r == "14 d" else ""}>{r}</span>' for r in ['15 m', '1 h', '24 h', '14 d', '90 d'])
    tb = ''.join(f'<span{" class=on" if i == 0 else ""}>{t}</span>' for i, t in enumerate(tabs))
    dk = ''.join(f'<span{" class=on" if i == 0 else ""}>{d}</span>' for i, d in enumerate(deck))
    return (f'  <div class="wordmark">BIRD<em>CAGE</em></div>\n  <div class="tabs">{tb}</div>\n'
            f'  <div class="status"><div class="ranges">{rng}</div>{STATUS[status]}<span class="who">tom (admin)</span></div>\n'
            f'  <div class="deck">{dk}</div>\n')


def page(title, css_extra, scenes):
    return (f'<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            f'<title>{title}</title>\n<style>{CSS}{css_extra}</style>\n</head>\n<body>\n\n' + '\n\n'.join(scenes) + '\n\n</body>\n</html>\n')


def scene(sid, label, body, tag):
    return f'<section class="scene" id="{sid}" aria-label="{label}">\n{body}  <div class="ibtn">i</div>\n  <div class="tag">{tag}</div>\n</section>'


def svg(parts):
    return '  <svg class="score" viewBox="0 0 1600 1000" aria-hidden="true">\n' + '\n'.join(p for p in parts if p) + '\n  </svg>\n'


QUIET_SUB = ('Nothing has touched a canary since <b>Thu 13 Aug</b> — one touch on canary-guest :23 from '
             '<span class="ip">198.51.100.200</span>, cleared with a note. The four canaries have phoned home every minute since; '
             'the newest heartbeat was three seconds ago.')
SILENT_SUB = ('Its last heartbeat was <b>21:58:19</b>, six minutes ago; it phones home every minute. A silent canary is not the quiet we '
              'want — the host may be down, or its firewall rule on the router may have moved. The other three are fine.')
NIGHT_SUB = ('<span class="ip">203.0.113.42</span> has reached <b>all four canaries in nine minutes</b> — ssh, then mysql, default passwords — '
             'and is still arriving. Three more visitors in the fortnight. Nothing here blocks: <b>lookback in mikroview ▸</b> to act.')

VISITOR_ROWS = [
    ('k-sw', '✱ SWEEP', '7× · 9 m · still arriving', '<span class="ip">203.0.113.42</span> walked <b>all four canaries</b> in nine minutes — ssh, then mysql, default passwords. Never seen before tonight.', '7×', '4 of 4', sweep),
    ('k-rp', '✱ REPEAT', '221× · 6 d · on schedule', '<span class="ip">198.51.100.7</span> knocks on <b>canary-iot :445</b> every ~20 minutes through the night, six nights running. Community-blocked since Tuesday.', '221×', '1 of 4', repeat),
    ('k-in', '✱ FROM INSIDE', '2× · 3 h ago', '<span class="ip">10.0.40.23</span>, a guest device, browsed <b>canary-lan :80</b> and tried /admin. Never auto-blocked (#33).', '2×', '1 of 4', inside),
    ('k-tc', '▲ ONE TOUCH', '1× · yesterday', '<span class="ip">192.0.2.88</span> logged in to <b>canary-srv :21</b> as anonymous, once, and left.', '1×', '1 of 4', touch),
]


def bird(top, c, status_html):
    return f'  <div class="bird" style="top:{top}px"><div class="n" style="color:{lane[c]}">canary-{c}</div><div class="s">{status_html}</div></div>\n'


QUIET_BIRD = {c: f'<span class="beat">● {beat_off[c]} s</span> · quiet 23 d' for c in lane}
NIGHT_BIRD = {'lan': '<span class="beat">● 9 s</span> · <span class="swept">✱ swept 21:55</span>', 'srv': '<span class="beat">● 41 s</span> · <span class="swept">✱ swept 21:56</span>',
              'iot': '<span class="beat">● 22 s</span> · <span class="swept">✱ swept 22:01</span> · <span class="rep">repeat :445</span>', 'guest': '<span class="beat">● 3 s</span> · <span class="swept">✱ swept 22:04</span>'}

# ================================================================ H — the quiet score
HX0, HX1 = 640, 1520
hcx = axis_fn(HX0, HX1)
H_DECK = ['THE SCORE', 'VISITORS', 'AUDIT LOG', 'SETTINGS']
H_TABS = ['canaries', 'visitors', 'audit log']
H_LEGEND = ('<span><span class="ln"></span>a canary\'s line is its heartbeat, unbroken</span><span><span class="gap"></span>a break is silence</span>'
            '<span>a tick on a canary\'s line is a visitor, by kind: <i style="background:var(--sweep)"></i>sweep <i style="background:var(--repeat)"></i>repeat '
            '<i style="background:var(--inside)"></i>from inside <i style="background:var(--touch)"></i>one touch</span>'
            '<span>dim marks are single heartbeats where the axis is stretched</span><span class="nw">— the brink · now</span>')


def h_quiet(silent):
    ys = [300, 400, 500, 600]
    parts = [axis(HX0, HX1, hcx, 100, QUIET_DAY), brink(HX1, 112, 660)]
    for y, c in zip(ys, lane):
        parts.append(canary_stave(HX0, HX1, hcx, y, c, silent_since=SILENT_LAST if (silent and c == 'iot') else None))
    body = chrome('silent' if silent else 'quiet', H_DECK, H_TABS) + svg(parts)
    body += '  <div class="grp" style="top:70px">the cage · sat 5 sep · 22:04:31</div>\n'
    if silent:
        body += '  <div class="hero" style="top:94px;width:560px">Quiet for <b class="ok">23 days</b> — but <b>canary-iot is silent.</b></div>\n'
        body += f'  <div class="sub" style="top:140px;width:540px">{SILENT_SUB}</div>\n'
        body += '  <div class="acts" style="top:222px"><span class="pill">open canary-iot ▸</span><span class="pill">lookback in mikroview ▸</span><span class="pill quiet">mark as maintenance</span></div>\n'
    else:
        body += '  <div class="hero" style="top:94px">Quiet for <b class="ok">23 days</b>.</div>\n'
        body += f'  <div class="sub" style="top:140px;width:540px">{QUIET_SUB}</div>\n'
    for y, c in zip(ys, lane):
        st = '<span class="off">○ silent 6 m 12 s</span> · last 21:58:19' if (silent and c == 'iot') else QUIET_BIRD[c]
        body += bird(y-9, c, st)
    body += '  <div class="grp" style="top:690px">visitors · 14 days · <b>none</b></div>\n'
    body += ('  <div class="quiet-line" style="top:712px;width:560px">No visitor in the window. An empty score is the cage working — '
             'the lines above are the only thing that should be moving.</div>\n')
    body += f'  <div class="legend" style="top:800px">{H_LEGEND}</div>\n'
    if silent:
        body += '  <div class="foot"><span>twenty-three quiet days · <b>one canary has stopped talking</b> — silence is only good news while the heartbeat keeps coming</span></div>\n'
    else:
        body += '  <div class="foot"><span>twenty-three quiet days · <span class="ok">all four phoning home</span> · nothing to act on</span></div>\n'
    return body


def h_night():
    cys = [240, 292, 344, 396]
    rys = [490, 574, 658, 742]
    parts = [axis(HX0, HX1, hcx, 100, NIGHT_DAY), brink(HX1, 112, 820), flag(hcx, 112, 820, 228)]
    for y, c in zip(cys, lane):
        parts.append(canary_stave(HX0, HX1, hcx, y, c, hits=hits_by[c]))
    for y, row in zip(rys, VISITOR_ROWS):
        parts.append(visitor_stave(HX0, HX1, hcx, y+42, row[6]))
    body = chrome('night', H_DECK, H_TABS) + svg(parts)
    body += '  <div class="grp" style="top:70px">the cage · fri 12 sep · <span class="r">1 flagged</span> · 232 hits today</div>\n'
    body += '  <div class="hero" style="top:94px;width:560px"><b class="r">One address is walking the cage.</b></div>\n'
    body += f'  <div class="sub" style="top:134px;width:540px">{NIGHT_SUB}</div>\n'
    for y, c in zip(cys, lane):
        body += bird(y-9, c, NIGHT_BIRD[c])
    body += '  <div class="grp" style="top:462px">visitors · 14 days · <b>4</b> · a tick on a visitor\'s line is coloured by which canary</div>\n'
    for y, (k, kd, sm, who, n, of, _) in zip(rys, VISITOR_ROWS):
        body += f'  <div class="row {k}" style="top:{y}px"><div class="kind">{kd}<small>{sm}</small></div><div class="who">{who}</div><div class="n">{n}<small>{of}</small></div></div>\n'
    body += f'  <div class="legend" style="top:850px">{H_LEGEND}</div>\n'
    body += '  <div class="foot"><span>a quiet fortnight until <b>21:55</b> tonight — <span class="r">one address is walking the cage right now</span></span></div>\n'
    return body


H = page('Birdcage · round 4 · H · The quiet score', '', [
    scene('h-quiet', 'The quiet score: a fortnight with no visitors, four canaries phoning home', h_quiet(False), 'H · THE QUIET SCORE · SCENE 1 · A QUIET FORTNIGHT'),
    scene('h-silent', 'The quiet score: a fortnight with no visitors, but one canary has stopped phoning home', h_quiet(True), 'H · THE QUIET SCORE · SCENE 2 · A CANARY GONE SILENT'),
    scene('h-night', 'The quiet score on the sweep night: canaries first, the four visitors beneath', h_night(), 'H · THE QUIET SCORE · SCENE 3 · THE SWEEP NIGHT'),
])

# ================================================================ I — the pulse
IX0, IX1 = 140, 1520
icx = axis_fn(IX0, IX1)
I_DECK = ['THE PULSE', 'VISITORS', 'AUDIT LOG', 'SETTINGS']
I_TABS = ['the pulse', 'visitors', 'audit log']
I_CSS = '  .hero, .sub, .grp, .quiet-line, .acts, .legend { left: 140px; }\n'
I_LEGEND = ('<span><span class="ln"></span>a line is a canary\'s heartbeat, unbroken</span><span><span class="gap"></span>a break is silence</span>'
            '<span>a tick is a visitor, by kind: <i style="background:var(--sweep)"></i>sweep <i style="background:var(--repeat)"></i>repeat '
            '<i style="background:var(--inside)"></i>from inside <i style="background:var(--touch)"></i>one touch</span>'
            '<span>its words sit beside it</span><span class="nw">— the brink · now</span>')


def lanelab(x, y, c, status_tspans):
    return f'<text x="{x}" y="{y-14}" class="lanelab" fill="{lane[c]}">canary-{c} <tspan dx="10">{status_tspans}</tspan></text>'


def i_quiet(silent):
    ys = [340, 480, 620, 760]
    parts = [axis(IX0, IX1, icx, 256, QUIET_DAY), brink(IX1, 268, 800)]
    for y, c in zip(ys, lane):
        s = (silent and c == 'iot')
        parts.append(canary_stave(IX0, IX1, icx, y, c, silent_since=SILENT_LAST if s else None))
        st = '<tspan class="al" fill="var(--ink)">○ silent 6 m 12 s</tspan><tspan> · last heartbeat 21:58:19</tspan>' if s else f'<tspan class="ok">● {beat_off[c]} s</tspan><tspan> · quiet 23 d</tspan>'
        parts.append(lanelab(IX0, y, c, st))
    body = chrome('silent' if silent else 'quiet', I_DECK, I_TABS) + svg(parts)
    body += '  <div class="grp" style="top:70px">the cage · sat 5 sep · 22:04:31</div>\n'
    if silent:
        body += '  <div class="hero" style="top:94px">Quiet for <b class="ok">23 days</b> — but <b>canary-iot is silent.</b></div>\n'
        body += f'  <div class="sub" style="top:134px;width:760px">{SILENT_SUB}</div>\n'
        body += '  <div class="acts" style="top:196px"><span class="pill">open canary-iot ▸</span><span class="pill">lookback in mikroview ▸</span><span class="pill quiet">mark as maintenance</span></div>\n'
    else:
        body += '  <div class="hero" style="top:94px">Quiet for <b class="ok">23 days</b>.</div>\n'
        body += f'  <div class="sub" style="top:134px;width:760px">{QUIET_SUB}</div>\n'
    body += '  <div class="chips" style="top:836px"><span>◎ visitors · 14 d ·</span><span class="chip">none — last <span class="ip">198.51.100.200</span> · one touch · 13 aug · cleared</span></div>\n'
    body += f'  <div class="legend" style="top:892px">{I_LEGEND}</div>\n'
    if silent:
        body += '  <div class="foot"><span>twenty-three quiet days · <b>one canary has stopped talking</b> — silence is only good news while the heartbeat keeps coming</span></div>\n'
    else:
        body += '  <div class="foot"><span>twenty-three quiet days · <span class="ok">all four phoning home</span> · nothing to act on</span></div>\n'
    return body


def i_night():
    ys = [340, 480, 620, 760]
    parts = [axis(IX0, IX1, icx, 256, NIGHT_DAY), brink(IX1, 268, 800), flag(icx, 268, 800, 312)]
    for y, c in zip(ys, lane):
        parts.append(canary_stave(IX0, IX1, icx, y, c, hits=hits_by[c]))
        parts.append(lanelab(IX0, y, c, {
            'lan': '<tspan class="ok">● 9 s</tspan><tspan> · </tspan><tspan class="al">✱ swept 21:55</tspan><tspan> · from inside 19:11</tspan>',
            'srv': '<tspan class="ok">● 41 s</tspan><tspan> · </tspan><tspan class="al">✱ swept 21:56</tspan><tspan> · one touch yesterday</tspan>',
            'iot': '<tspan class="ok">● 22 s</tspan><tspan> · </tspan><tspan class="al">✱ swept 22:01</tspan><tspan> · </tspan><tspan class="rp">repeat :445 · 221×</tspan>',
            'guest': '<tspan class="ok">● 3 s</tspan><tspan> · </tspan><tspan class="al">✱ swept 22:04</tspan>'}[c]))
        # the words beside the ticks
        items = [(a, t) for a, l, t in sweep if l == c]
        for j, (a, t) in enumerate(items):
            x = icx(a)
            parts.append(f'<text x="{x-6:.1f}" y="{y + (22 if j % 2 == 0 else -10)}" class="lyric" text-anchor="end">{t}</text>')
        if c == 'iot':
            x = icx(321)
            parts.append(f'<text x="{x-6:.1f}" y="{y-10}" class="lyric dim" text-anchor="end">198.51.100.7 · :445 · the 221st knock, 21:59</text>')
        if c == 'lan':
            x = icx(10389)
            parts.append(f'<text x="{x:.1f}" y="{y-10}" class="lyric dim" text-anchor="middle">10.0.40.23 · :80 then /admin · 19:11</text>')
        if c == 'srv':
            x = icx(153951)
            parts.append(f'<text x="{x:.1f}" y="{y+22}" class="lyric dim" text-anchor="middle">192.0.2.88 · anonymous ftp · yesterday 03:18</text>')
    body = chrome('night', I_DECK, I_TABS) + svg(parts)
    body += '  <div class="grp" style="top:70px">the cage · fri 12 sep · <span class="r">1 flagged</span> · 232 hits today</div>\n'
    body += '  <div class="hero" style="top:94px"><b class="r">One address is walking the cage.</b></div>\n'
    body += f'  <div class="sub" style="top:134px;width:760px">{NIGHT_SUB}</div>\n'
    body += ('  <div class="chips" style="top:836px"><span>◎ visitors · 14 d ·</span>'
             '<span class="chip k-sw"><b>✱ sweep</b> <span class="ip">203.0.113.42</span> · 7× · 4 of 4</span>'
             '<span class="chip k-rp"><b>✱ repeat</b> <span class="ip">198.51.100.7</span> · 221× · iot :445</span>'
             '<span class="chip k-in"><b>✱ from inside</b> <span class="ip">10.0.40.23</span> · 2× · lan :80</span>'
             '<span class="chip k-tc"><b>▲ one touch</b> <span class="ip">192.0.2.88</span> · 1× · srv :21</span></div>\n')
    body += f'  <div class="legend" style="top:892px">{I_LEGEND}</div>\n'
    body += '  <div class="foot"><span>a quiet fortnight until <b>21:55</b> tonight — <span class="r">one address is walking the cage right now</span></span></div>\n'
    return body


I = page('Birdcage · round 4 · I · The pulse', I_CSS, [
    scene('i-quiet', 'The pulse: four canary heartbeats across a quiet fortnight, nothing else', i_quiet(False), 'I · THE PULSE · SCENE 1 · A QUIET FORTNIGHT'),
    scene('i-silent', 'The pulse: one heartbeat has stopped', i_quiet(True), 'I · THE PULSE · SCENE 2 · A CANARY GONE SILENT'),
    scene('i-night', 'The pulse on the sweep night: every visitor is a tick on a canary line, with its words beside it', i_night(), 'I · THE PULSE · SCENE 3 · THE SWEEP NIGHT'),
])

open('direction-h-quiet-score.html', 'w').write(H)
open('direction-i-pulse.html', 'w').write(I)
print('ok')
