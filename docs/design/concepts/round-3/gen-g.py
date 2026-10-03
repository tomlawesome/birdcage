#!/usr/bin/env python3
"""Generate the stave SVG for direction G (the score) and splice it into
direction-g-score.html between <!--S1-->…<!--/S1--> etc. markers.
Run from this directory: python3 gen-g.py"""
import re

NOW = 22*3600 + 4*60 + 31
X0, X1 = 640, 1520
# compressed axis for the 14-day view: (ago_from, ago_to, x_from, x_to)
SEG = [(0, 900, 1520, 1220), (900, 3600, 1220, 1040), (3600, 86400, 1040, 840), (86400, 1209600, 840, 640)]


def cx(ago):
    for a0, a1, x0, x1 in SEG:
        if ago <= a1:
            return x0 + (ago-a0)/(a1-a0)*(x1-x0)
    return X0


def lx(ago):  # linear, last hour
    return X1 - (ago/3600)*(X1-X0)


lane = {'lan': 'var(--lan)', 'srv': 'var(--srv)', 'iot': 'var(--iot)', 'guest': 'var(--guest)'}
kind = {'sw': 'var(--sweep)', 'rp': 'var(--repeat)', 'in': 'var(--inside)', 'tc': 'var(--touch)'}
sweep = [(0, 'guest', 'root / 123456'), (29, 'guest', 'admin / admin'), (164, 'iot', 'root / toor'),
         (429, 'srv', 'mysql root / (empty)'), (453, 'srv', 'root / password'), (531, 'lan', 'root / root'),
         (532, 'lan', 'session · libssh2')]
# 221 knocks: a 12-hour run each night for six nights, every 20 minutes
repeat = [(321 + d*86400 + k*1200, 'iot') for d in range(6) for k in range(37)][:221]
inside = [(10389, 'lan'), (10407, 'lan')]
touch = [(153951, 'srv')]
beat_off = {'lan': 9, 'srv': 41, 'iot': 22, 'guest': 3}
hits_by = {'guest': [(0, 'sw'), (29, 'sw')], 'iot': [(164, 'sw')] + [(a, 'rp') for a, _ in repeat],
           'srv': [(429, 'sw'), (453, 'sw'), (153951, 'tc')], 'lan': [(531, 'sw'), (532, 'sw'), (10389, 'in'), (10407, 'in')]}


def tick(x, y, h, col, op=1, w=2.2):
    return f'<line x1="{x:.1f}" y1="{y-h/2}" x2="{x:.1f}" y2="{y+h/2}" stroke="{col}" stroke-width="{w}" stroke-linecap="round" opacity="{op}"/>'


def stave(y, ticks, xf=cx):
    dense = len(ticks) > 50
    out = [f'<line x1="{X0}" y1="{y}" x2="{X1}" y2="{y}" class="stv"/>']
    for t in ticks:
        out.append(tick(xf(t[0]), y, 14, lane[t[1]], .55 if dense else 1, 1.6 if dense else 2.2))
    return '\n'.join(out)


def axis(y):
    out = []
    for lab, x in [('14 d', 640), ('24 h', 840), ('1 h', 1040), ('15 m', 1220)]:
        out.append(f'<text x="{x}" y="{y}" class="ax">{lab}</text><line x1="{x}" y1="{y+6}" x2="{x}" y2="{y+14}" class="axt"/>')
    out.append(f'<text x="{X1}" y="{y}" class="ax now" text-anchor="end">NOW · 22:04:31</text>')
    out.append(f'<text x="740" y="{y+22}" class="axs">13 days, compressed</text><text x="940" y="{y+22}" class="axs">23 hours, compressed</text><text x="1370" y="{y+22}" class="axs">the last quarter hour, stretched</text>')
    return '\n'.join(out)


def brink(y0, y1):
    return f'<line x1="{X1}" y1="{y0}" x2="{X1}" y2="{y1}" class="brink"/>'


def flag(y0, y1, ylab, xf=cx, ago=532, label='✱ 21:55 · sweep born'):
    x = xf(ago)
    return f'<line x1="{x:.1f}" y1="{y0}" x2="{x:.1f}" y2="{y1}" class="flagline"/><text x="{x-6:.1f}" y="{ylab}" class="flag-t" text-anchor="end">{label}</text>'


def canary_staves(y0, step):
    out = []
    for i, c in enumerate(['lan', 'srv', 'iot', 'guest']):
        y = y0 + i*step
        out.append(f'<line x1="{X0}" y1="{y}" x2="{X1}" y2="{y}" stroke="{lane[c]}" stroke-width="1" opacity=".45"/>')
        a = beat_off[c]
        while a < 900:  # heartbeats only where the axis is stretched
            out.append(f'<rect x="{cx(a)-.8:.1f}" y="{y-2}" width="1.6" height="4" fill="var(--ink-3)" opacity=".5"/>')
            a += 60
        for ago, k in hits_by.get(c, []):
            out.append(tick(cx(ago), y, 12, kind[k], .55 if k == 'rp' else 1, 1.6 if k == 'rp' else 2.2))
    return '\n'.join(out)


# ---- scene 1: rows at 120/204/288/372 (84 tall, stave at +42); canaries at 520 step 52
S1 = [axis(100), brink(112, 720), flag(112, 720, 150)]
S1 += [stave(162, sweep), stave(246, repeat), stave(330, inside), stave(414, touch), canary_staves(520, 52)]

# ---- scene 3: sweep row open at 120, drawer 204→~430, rows 442/526/610, canaries 700 step 36
S3 = [axis(100), brink(112, 880), flag(112, 880, 150), stave(162, sweep)]
for i, c in enumerate(['lan', 'srv', 'iot', 'guest']):
    y = 244 + i*56
    S3.append(f'<line x1="{X0}" y1="{y}" x2="{X1}" y2="{y}" stroke="{lane[c]}" stroke-width="1" opacity=".35"/>')
    S3.append(f'<text x="{X0}" y="{y-7}" class="lanelab" fill="{lane[c]}">canary-{c}</text>')
    S3 += [tick(cx(a), y, 12, 'var(--sweep)') for a, l, _ in sweep if l == c]
S3 += [stave(496, repeat), stave(580, inside), stave(664, touch), canary_staves(750, 36)]

# ---- scene 2: linear last hour, filtered to the sweep
S2 = []
for lab, m in [('21:05', 59), ('21:15', 49), ('21:25', 39), ('21:35', 29), ('21:45', 19), ('21:55', 9)]:
    x = lx(m*60+31)
    S2.append(f'<text x="{x:.1f}" y="100" class="ax" text-anchor="middle">{lab}</text><line x1="{x:.1f}" y1="106" x2="{x:.1f}" y2="114" class="axt"/>')
S2.append(f'<text x="{X0}" y="122" class="axs" style="text-anchor:start">one hour, linear — nothing compressed</text>')
S2.append(f'<text x="{X1}" y="100" class="ax now" text-anchor="end">NOW · 22:04:31</text>')
S2.append(brink(112, 530))
S2.append(flag(112, 530, 150, lx, 532, '✱ 21:55:39 · first sight · sweep born'))
S2.append(stave(162, sweep, lx))
for i, c in enumerate(['lan', 'srv', 'iot', 'guest']):
    y = 262 + i*80
    S2.append(f'<line x1="{X0}" y1="{y}" x2="{X1}" y2="{y}" stroke="{lane[c]}" stroke-width="1" opacity=".45"/>')
    a = beat_off[c]
    while a < 3600:
        S2.append(f'<rect x="{lx(a)-.8:.1f}" y="{y-2}" width="1.6" height="4" fill="var(--ink-3)" opacity=".5"/>')
        a += 60
    items = [(a, l, t) for a, l, t in sweep if l == c]
    for j, (a, l, t) in enumerate(items):
        x = lx(a)
        S2.append(tick(x, y, 14, 'var(--sweep)'))
        S2.append(f'<text x="{x-6:.1f}" y="{y + (20 if j % 2 == 0 else -12)}" class="lyric" text-anchor="end">{t}</text>')
    if c == 'iot':
        for a, _ in repeat:
            if a < 3600:
                S2.append(tick(lx(a), y, 14, 'var(--repeat)', .8))
                S2.append(f'<text x="{lx(a)-6:.1f}" y="{y-12}" class="lyric dim" text-anchor="end">198.51.100.7 · :445 · repeat</text>')

p = 'direction-g-score.html'
s = open(p).read()
for tag, body in [('S1', S1), ('S2', S2), ('S3', S3)]:
    s = re.sub(rf'<!--{tag}-->.*?<!--/{tag}-->', lambda m: f'<!--{tag}-->\n' + '\n'.join(body) + f'\n<!--/{tag}-->', s, flags=re.S)
open(p, 'w').write(s)
print('ok')
