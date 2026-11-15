#!/usr/bin/env python3
"""Round 10: smoked glass, part of birdcage (#8, slice B). Round 9's S carried forward
(frosted panes on hinges in a lit room, the door-to-door motion) and tied into the
ratified shell (ADR-0004, round 6 M; round 7 O) three ways, each a different answer to
"how is this glass part of birdcage": V the door stands in the trace's own column,
W the brink stands in the room, X the frost is over the cage's own light.
Same copy, data and eight scenes as round 9; palette, type roots and chrome are round
6/7's, copied so the round stands alone.
Run here: python3 gen.py  ->  direction-{v,w,x}-*.html, motion-{v,w,x}.html"""
import html
import random

# ---------------------------------------------------------------- data story (round 9's)
VER = '0.2.0'
DAY = 'sat 14 nov'
NOW = '09:18:04'
IP = '192.0.2.10'            # ada's laptop
SETUP = '7KQW-93HD-2MXF'     # the one-time setup code from the server log
KEY = 'JBSW Y3DP EHPK 3PXP JBSW Y3DP EHPK 3PXP'
RECOVERY = ['k7mq-4d2x', 'p3vn-8rtc', 'h2wd-6yqa', 'z9lf-1sbe', 'm4cr-7hjn',
            't6xp-2vgk', 'b8qn-5wmz', 'r1dk-9pft', 'w5hs-3lcy', 'g2tb-8nxv']
SCENES = [('signin', 'sign in'), ('factor', 'second factor'), ('firstrun', 'first run'),
          ('enrol', 'enrol an authenticator'), ('codes', 'recovery codes, shown once'),
          ('timeout', 'timed out'), ('refused', 'refused'), ('locked', 'too many tries')]
# the clock on each door, for the brink
TIMES = {'signin': '09:18:04', 'factor': '09:18:09', 'firstrun': '09:18:04', 'enrol': '09:18:14',
         'codes': '09:18:41', 'timeout': '09:18:04', 'refused': '09:18:07', 'locked': '09:18:48'}
DIRS = [('v', 'the column', 'direction-v-the-column.html'),
        ('w', 'the brink', 'direction-w-the-brink.html'),
        ('x', 'through the frost', 'direction-x-through-the-frost.html')]

# frosted glass grain: one tiny SVG, never animated
NOISE = ("url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='180' height='180'%3E"
         "%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.85' numOctaves='3' stitchTiles='stitch'/%3E"
         "%3CfeColorMatrix values='0 0 0 0 1 0 0 0 0 1 0 0 0 0 1 0 0 0 .6 0'/%3E%3C/filter%3E"
         "%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E\")")


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


def qr_svg(size=196, cls='qr'):
    g = qr_modules()
    n = len(g)
    m = size / n
    rects = ''.join(f'<rect x="{c*m:.1f}" y="{r*m:.1f}" width="{m+.2:.1f}" height="{m+.2:.1f}"/>'
                    for r in range(n) for c in range(n) if g[r][c])
    return (f'<svg class="{cls}" width="{size}" height="{size}" viewBox="0 0 {size} {size}" role="img" '
            f'aria-label="QR code for the authenticator app (placeholder pattern)">{rects}</svg>')


# ---------------------------------------------------------------- the shell's geometry (round 6 M at 1440 wide)
GX = 54            # the grid's left edge: group label, hero, prose, tiles, legend
X0, X1 = 190, 1368  # the band: lane labels end in the gutter at X0; the brink stands at X1
BANDY = 300        # the first of four lines, 12 px apart
TILEY, TILEW = 470, 318

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
  .scene { position: relative; width: 1440px; height: 900px; margin: 0 auto 40px; overflow: hidden; background: var(--void); border-bottom: 1px solid var(--hair-2); }
  .tag { position: absolute; left: 50%; transform: translateX(-50%); bottom: 0; font: 9.5px var(--mono); letter-spacing: .12em; color: var(--ink-3); z-index: 9; text-transform: uppercase; }
  .wordmark { position: absolute; top: 18px; left: 24px; font-weight: 800; font-size: 15px; letter-spacing: .04em; z-index: 3; }
  .wordmark em { font-style: normal; color: var(--accent); }
  .ver { position: absolute; top: 20px; right: 40px; font: 11px var(--mono); color: var(--ink-3); z-index: 3; }
  .ver b { color: var(--ink-2); font-weight: 500; }
  .ibtn { position: absolute; left: 14px; bottom: 12px; width: 18px; height: 18px; border-radius: 50%; border: 1px solid var(--hair-2); color: var(--ink-3); font: italic 600 11px Georgia, serif; text-align: center; line-height: 16px; z-index: 3; }
  .foot { position: absolute; left: 0; right: 0; bottom: 16px; text-align: center; font: 12.5px var(--sans); color: var(--ink-2); z-index: 3; }
  .foot b { color: var(--ink); font-weight: 600; }
  input, button { font: inherit; color: inherit; }
  input { background: none; border: 0; outline: 0; padding: 0; margin: 0; }
  button { background: none; border: 0; padding: 0; margin: 0; cursor: pointer; }
  button:focus-visible, input:focus-visible { outline: 2px solid var(--accent); outline-offset: 3px; }
  .ip { font-family: var(--mono); }
  .caret { display: inline-block; width: 1.5px; height: 1em; background: var(--accent); vertical-align: -.15em; margin-left: 1px; }
  .sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); }
  @media (prefers-reduced-motion: no-preference) {
    .caret { animation: blink 1.1s steps(2, start) infinite; }
    @keyframes blink { to { visibility: hidden; } }
  }

  /* the ratified shell, round 6 M, quiet: behind the timed-out door, dimmed, and the first view after the last door */
  .shell { position: absolute; inset: 0; }
  .shell .tabs { position: absolute; top: 21px; left: 150px; display: flex; gap: 20px; font: 12px var(--sans); color: var(--ink-3); }
  .shell .tabs .on { color: var(--ink); position: relative; }
  .shell .tabs .on::after { content: ''; position: absolute; left: 0; right: 0; bottom: -4px; height: 1px; background: var(--accent); }
  .shell .status { position: absolute; top: 20px; right: 40px; display: flex; gap: 16px; align-items: center; font: 11px var(--mono); color: var(--ink-2); }
  .shell .status .dot { display: inline-block; width: 7px; height: 7px; border-radius: 50%; background: var(--ok); margin-right: 5px; vertical-align: 1px; }
  .shell .status .who { color: var(--ink-3); border: 1px solid var(--hair-2); border-radius: 999px; padding: 2px 10px; }
  .shell .ranges { display: flex; gap: 4px; } .shell .ranges span { color: var(--ink-3); padding: 2px 9px; border-radius: 4px; }
  .shell .ranges .on { color: var(--ink); background: var(--raised); border: 1px solid var(--hair-2); }
  .shell .deck { position: absolute; right: 8px; top: 50%; transform: translateY(-50%); display: flex; flex-direction: column; gap: 30px; align-items: center; }
  .shell .deck span { writing-mode: sideways-lr; color: var(--ink-3); font: 500 9.5px var(--mono); letter-spacing: .22em; }
  .shell .deck .on { color: var(--ink); font-size: 12px; letter-spacing: .26em; }
  .shell .grp { position: absolute; left: 54px; top: 74px; font: 600 9.5px var(--mono); letter-spacing: .16em; color: var(--ink-3); text-transform: uppercase; }
  .shell .hero { position: absolute; left: 54px; top: 96px; font: 500 26px/1.2 var(--sans); letter-spacing: -.01em; } .shell .hero b { color: var(--ok); font-weight: 500; }
  .shell .sub { position: absolute; left: 54px; top: 140px; width: 820px; font: 13px/1.55 var(--sans); color: var(--ink-2); }
  .shell svg.band { position: absolute; inset: 0; }
  .shell .bandlab { font: 600 10.5px var(--mono); } .shell .ax { font: 600 9.5px var(--mono); letter-spacing: .12em; fill: var(--ink-3); } .shell .ax.now { fill: var(--now); }
  .shell .axs { font: 9.5px var(--sans); fill: var(--ink-3); opacity: .8; }
  .shell .tiles { position: absolute; left: 54px; top: 470px; display: flex; gap: 14px; }
  .shell .tile { --b: var(--lan); position: relative; width: 318px; height: 96px; padding: 12px 14px; border: 1px solid var(--b); border-radius: 8px; background: var(--raised); }
  .shell .tile .n { font: 700 12px var(--mono); color: var(--b); } .shell .tile .n small { font-weight: 500; color: var(--ink-3); margin-left: 8px; }
  .shell .tile .s { font: 11px var(--mono); color: var(--ink-2); margin-top: 6px; } .shell .tile .s i { display: inline-block; width: 7px; height: 7px; border-radius: 50%; background: var(--ok); margin-right: 6px; vertical-align: 0; } .shell .tile .s b { color: var(--ok); font-weight: 500; }
  .shell .tile .p { font: 10px var(--mono); color: var(--ink-3); margin-top: 8px; }
  .shell .tile .big { position: absolute; right: 14px; top: 10px; font: 600 20px var(--sans); color: var(--ink); text-align: right; } .shell .tile .big small { display: block; font: 600 9px var(--mono); color: var(--ink-3); letter-spacing: .12em; text-transform: uppercase; }
  .shell .events { position: absolute; left: 54px; top: 600px; font: 600 9.5px var(--mono); letter-spacing: .16em; color: var(--ink-3); text-transform: uppercase; }
  .shell .events p { margin: 10px 0 0; font: italic 13px var(--sans); color: var(--ink-2); letter-spacing: 0; text-transform: none; }
  .shell .legend { position: absolute; left: 54px; bottom: 60px; font: 11px var(--sans); color: var(--ink-3); display: flex; gap: 22px; }
  .shell .legend .nw { color: var(--now); }
  .shell .bfoot { position: absolute; left: 0; right: 40px; bottom: 14px; text-align: center; font: 12.5px var(--sans); color: var(--ink-2); }
  .shell .bfoot b { color: var(--ok); font-weight: 600; }
  .scrim { position: absolute; inset: 0; background: rgba(6,8,14,.72); }
"""

LANES = [('canary-lan', 'lan', 'ssh 22 · smb 445 · http 80', 9), ('canary-srv', 'srv', 'ssh 22 · rdp 3389 · mysql 3306', 41),
         ('canary-iot', 'iot', 'telnet 23 · ssh 22 · smb 445', 22), ('canary-guest', 'guest', 'http 80 · ssh 22', 3)]


def band_svg(now, brink=True):
    parts = []
    for i, (name, lane, _, _) in enumerate(LANES):
        y = BANDY + i * 12
        beats = ''.join(f'<rect x="{x}" y="{y-2}" width="1.4" height="4" fill="var(--ink-3)" opacity=".55"/>'
                        for x in range(1140 + i * 9, X1, 36))
        parts.append(f'<text class="bandlab" x="{X0-12}" y="{y+3.5}" text-anchor="end" fill="var(--{lane})">{name}</text>'
                     f'<line x1="{X0}" y1="{y}" x2="{X1}" y2="{y}" stroke="var(--{lane})" stroke-width="1.2" opacity=".7"/>{beats}')
    ax = BANDY + 70
    for x, t in [(X0, '14 d'), (560, '24 h'), (900, '1 h'), (1140, '15 m')]:
        parts.append(f'<line x1="{x}" y1="{ax-6}" x2="{x}" y2="{ax}" stroke="var(--hair-2)"/><text class="ax" x="{x}" y="{ax+16}">{t.upper()}</text>')
    parts.append(f'<text class="axs" x="{(X0+560)/2:.0f}" y="{ax+34}" text-anchor="middle">fourteen days, squeezed</text>'
                 f'<text class="axs" x="{(560+900)/2:.0f}" y="{ax+34}" text-anchor="middle">23 hours, compressed</text>'
                 f'<text class="axs" x="{(1140+X1)/2:.0f}" y="{ax+34}" text-anchor="middle">the last quarter hour, stretched</text>')
    if brink:
        parts.append(f'<text class="ax now" x="{X1}" y="{ax+16}" text-anchor="end">NOW · {now}</text>'
                     f'<line x1="{X1}" y1="200" x2="{X1}" y2="{ax+4}" stroke="var(--now)" stroke-width="1.6"/>')
    return f'<svg class="band" viewBox="0 0 1440 900">{"".join(parts)}</svg>'


def shell(now, dim=False, deck=True, cls=''):
    """The quiet shell: the dashboard as it was when the session idled out (dimmed),
    or the first view after the last door."""
    tiles = ''.join(f'<div class="tile" style="--b:var(--{lane})"><div class="n">{name}<small>on {lane}</small></div>'
                    f'<div class="s"><i></i><b>{beat} s</b> · every minute · quiet 14 d</div><div class="p">{ports}</div>'
                    f'<div class="big">0<small>hits · 14 d</small></div></div>' for name, lane, ports, beat in LANES)
    rng = ''.join(f'<span{" class=on" if r == "14 d" else ""}>{r}</span>' for r in ['15 m', '1 h', '24 h', '14 d', '90 d'])
    dk = '<div class="deck"><span class="on">the trace</span><span>visitors</span><span>audit log</span><span>settings</span></div>' if deck else ''
    return (f'<div class="shell {cls}" aria-hidden="true">'
            '<div class="wordmark">BIRD<em>CAGE</em></div>'
            '<div class="tabs"><span class="on">the cage</span><span>visitors</span><span>audit log</span></div>'
            f'<div class="status"><div class="ranges">{rng}</div><span><i class="dot"></i>QUIET · 4 of 4 phoning home</span><span>0 visitors · 14 d</span><span class="who">ada (admin)</span></div>'
            f'<div class="grp">the cage · {DAY} · {now}</div>'
            '<div class="hero">Quiet for <b>14 days</b>.</div>'
            '<div class="sub">Nothing has touched any of the four canaries in fourteen days. All four are phoning home every minute; the last self-test at 04:00 reached every service.</div>'
            f'{band_svg(now)}'
            f'<div class="tiles">{tiles}</div>'
            '<div class="events">events · 14 days · none<p>Nothing in the window. A flat trace is the cage working — the only things moving on this page are the heartbeats.</p></div>'
            '<div class="legend"><span>— a line is a canary\'s heartbeat, unbroken</span><span>- - - a drop is silence</span><span>a rise is a visitor, its words at the top</span><span class="nw">— the brink · now</span></div>'
            f'<div class="bfoot">fourteen quiet days · <b>all four phoning home</b> · nothing to act on</div>{dk}'
            '</div>' + ('<div class="scrim"></div>' if dim else ''))


def page(title, css, body):
    return (f'<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            f'<title>{title}</title>\n<style>{BASE}{css}</style>\n</head>\n<body>\n\n{body}\n\n</body>\n</html>\n')


def scene(sid, aria, body, tag, cls=''):
    return (f'<section class="scene {cls}" id="{sid}" role="region" aria-label="{html.escape(aria)}">\n{body}\n'
            f'  <div class="ibtn" aria-hidden="true">i</div>\n  <div class="tag">{tag}</div>\n</section>')


def chrome():
    return f'  <div class="wordmark">BIRD<em>CAGE</em></div>\n  <div class="ver">birdcage <b>{VER}</b></div>\n'


def inp(name, value, label, kind='text', live=False):
    c = '<span class="caret"></span>' if live else ''
    i = f'<input type="{kind}" name="{name}" value="{html.escape(value)}" aria-label="{label}" autocomplete="off">'
    return (c + i) if (live and not value) else (i + c)


def fld(label, box, cls='', note=''):
    n = f'<div class="note{" ok" if note.startswith("accepted") else ""}">{note}</div>' if note else ''
    return f'<div class="fld {cls}"><label>{label}</label><div class="box">{box}</div>{n}</div>'


def acts(primary, alts, meta='', go='go'):
    ab = ''.join(f'<button class="alt {c}">{t}</button>' for t, c in alts)
    m = f'<span class="meta">{meta}</span>' if meta else ''
    return f'<div class="acts"><button class="{go}">{primary}</button>{ab}<span class="sp"></span>{m}</div>'


def foot(t):
    return f'<div class="foot">{t}</div>'


DIGITS_417 = '<span class="digits">417<span class="blank">···</span></span><span class="caret"></span>'
DIGITS_NONE = '<span class="digits"><span class="blank">······</span></span><span class="caret"></span>'


# ---------------------------------------------------------------- the eight scenes, as content
# Plain security-UI copy (owner, 2026-11-15): the fact and the next step, nothing else.
def scenes_for(D):
    S = []
    L, N = D.letter, D.name
    tag = lambda i: f'{L.upper()} · {N} · scene {i} · {SCENES[i-1][1]}'
    sid = lambda k: f'{L}-{k}'
    FROM = f'Connecting from <span class="ip">{IP}</span>.'
    signin_fields = '<div class="fields">' + fld('username', inp('user', 'ada', 'username'), 'live') + fld('password', inp('pass', '', 'password', 'password', live=True), 'live') + '</div>'
    signin_alts = [('Use a passkey', ''), ('Sign in with SSO', 'quiet')]

    # 1 sign in
    d = D.door(f'sign in · step 1 of 2 · {DAY} · {NOW}', 'Sign in', FROM, signin_fields, acts('Sign in', signin_alts))
    body = chrome() + D.hall([], d, ['Authentication code'], 'signin')
    S.append(scene(sid('signin'), f'{L.upper()}, {N}: sign in', body, tag(1), 'g ' + L))

    # 2 second factor
    d = D.door(f'sign in · step 2 of 2 · {DAY} · 09:18:09', 'Enter your authentication code',
               'Enter the six-digit code from your authenticator app.',
               '<div class="fields one">' + fld('authentication code', DIGITS_417, 'live', 'This code is valid for another 19 s.') + '</div>',
               acts('Continue', [('Use a recovery code', 'quiet')], 'Last sign-in: Thu 13 Nov, 09:41'))
    body = chrome() + D.hall(['Password'], d, [], 'factor')
    S.append(scene(sid('factor'), f'{L.upper()}, {N}: second factor', body, tag(2), 'g ' + L))

    # 3 first run
    d = D.door(f'first run · step 1 of 3 · {DAY} · {NOW}', 'Create the first administrator',
               f'No accounts exist yet. Enter the setup code printed in the server log at startup, then choose a username and password. The code expires at 09:27.',
               D.log(f'09:12:04 birdcage {VER} · no accounts · <b>setup code {SETUP}</b> · valid until 09:27')
               + '<div class="fields">' + fld('setup code', f'<span class="mono">{SETUP}</span>', 'live', 'Printed in the server log')
               + fld('username', inp('user', 'ada', 'username for the first administrator'), 'live', 'Lower-case letters, digits, dots and dashes')
               + fld('password', inp('pass', '••••••••••••••', 'password', 'password'), 'live', 'At least 12 characters')
               + fld('confirm password', inp('pass2', '•••••••', 'confirm password', 'password', live=True), 'live') + '</div>',
               acts('Create administrator', [('Sign in with SSO instead', 'quiet')]), 'tall')
    body = chrome() + D.hall([], d, ['Authenticator', 'Recovery codes'], 'firstrun')
    S.append(scene(sid('firstrun'), f'{L.upper()}, {N}: first run', body, tag(3), 'g ' + L))

    # 4 enrol
    inner = D.two(qr_svg(D.qr), '<div class="fields one wide">'
                  + fld('key', f'<span class="mono key">{KEY}</span>', 'set', 'Account birdcage:ada · time-based · 6 digits · 30 s')
                  + fld('code from the app', DIGITS_NONE, 'live') + '</div>')
    d = D.door(f'first run · step 2 of 3 · {DAY} · 09:18:14', 'Set up an authenticator app',
               'Password accounts require a second factor. Scan the QR code or enter the key in an authenticator app, then enter the code it shows. A passkey can be added later in settings.',
               inner, acts('Confirm', [], 'The key is shown once.'), 'wide')
    body = chrome() + D.hall(['Administrator'], d, ['Recovery codes'], 'enrol')
    S.append(scene(sid('enrol'), f'{L.upper()}, {N}: enrol an authenticator', body, tag(4), 'g ' + L))

    # 5 recovery codes
    d = D.door(f'first run · step 3 of 3 · {DAY} · 09:18:41', 'Save your recovery codes',
               'Each code can be used once in place of your authenticator app. Store them somewhere safe, away from this computer. They will not be shown again.',
               D.codes(), acts('Continue', [('Copy', ''), ('Download', ''), ('Print', 'quiet')], '10 codes · none used'), 'wide')
    body = chrome() + D.hall(['Administrator', 'Authenticator'], d, [], 'codes')
    S.append(scene(sid('codes'), f'{L.upper()}, {N}: recovery codes shown once', body, tag(5), 'g ' + L))

    # 6 timed out (ADR-0016 §6; owner answer 5a: within the day the password alone carries on)
    d = D.door(f'sign in · session expired · {DAY} · {NOW}', 'Session expired',
               'Your session expired at 08:52 after an hour of inactivity. The page behind this dialog is <b>26 minutes</b> old. '
               'Enter your password to continue. A full sign-in, including your authentication code, is required again by <b>Sunday 07:31</b>.',
               '<div class="fields one">' + fld('password', inp('pass', '', 'password', 'password', live=True), 'live', 'A passkey can also be used.') + '</div>',
               acts('Continue', [('Sign in as a different user', 'quiet')]))
    body = shell('08:52:10', dim=True) + D.hall(['Signed in 07:31'], d, [], 'timeout')
    S.append(scene(sid('timeout'), f'{L.upper()}, {N}: timed out, a door over the dimmed dashboard', body, tag(6), 'g ' + L))

    # 7 refused
    d = D.door(f'sign in · step 1 of 2 · {DAY} · 09:18:07', 'Sign in', FROM,
               signin_fields + D.said('Incorrect username or password.', '4 attempts left'),
               acts('Sign in', signin_alts), 'refused')
    body = chrome() + D.hall([], d, ['Authentication code'], 'refused')
    S.append(scene(sid('refused'), f'{L.upper()}, {N}: refused, wrong password', body, tag(7), 'g ' + L))

    # 8 too many tries
    d = D.door(f'sign in · paused · {DAY} · 09:18:48', 'Too many attempts',
               f'Sign-in for this username from <span class="ip">{IP}</span> is paused after 5 failed attempts. Try again at <b>09:23</b>.',
               D.wait('4:12', 'until 09:23:00')
               + '<div class="fields">' + fld('username', 'ada', 'off') + fld('password', '', 'off', '5 failed attempts between 09:18:07 and 09:18:48') + '</div>',
               acts('Sign in', signin_alts, 'Passkey and SSO sign-in are not paused.', 'go off'), 'locked')
    body = chrome() + D.hall([], d, ['Authentication code'], 'locked')
    S.append(scene(sid('locked'), f'{L.upper()}, {N}: too many tries, wait', body, tag(8), 'g ' + L))
    return S


# ---------------------------------------------------------------- shared door-content css (round 9's)
CONTENT = """
  .door .step { font: 600 9.5px var(--mono); letter-spacing: .18em; color: var(--ink-3); text-transform: uppercase; }
  .door .sub { font: 14.5px/1.55 var(--sans); color: var(--ink-2); max-width: 62ch; }
  .door .sub b { color: var(--ink); font-weight: 600; } .door .sub .ip { color: var(--ink); font-size: 13.5px; }
  .door .fields { margin-top: 26px; display: grid; grid-template-columns: 1fr 1fr; gap: 22px 40px; }
  .door .fields.one { grid-template-columns: 1fr; max-width: 420px; } .door .fields.wide { max-width: none; }
  .door .fld label { display: block; font: 600 9.5px var(--mono); letter-spacing: .18em; color: var(--ink-3); text-transform: uppercase; margin-bottom: 7px; }
  .door .fld .box { height: 46px; display: flex; align-items: center; font: 18px var(--sans); color: var(--ink); }
  .door .fld .box input { width: 100%; font: inherit; }
  .door .fld .box .mono { font: 500 17px var(--mono); letter-spacing: .03em; }
  .door .fld .box .digits { font: 500 27px var(--mono); letter-spacing: .5em; } .door .fld .box .digits .blank { color: var(--ink-3); }
  .door .fld .note { margin-top: 7px; font: 11.5px var(--sans); color: var(--ink-3); } .door .fld .note.ok { color: var(--ok); }
  .door .fld.set .box { color: var(--ink-2); } .door .fld.off .box { color: var(--ink-3); }
  .door .acts { margin-top: auto; display: flex; align-items: center; gap: 14px; padding-top: 30px; }
  .door .acts .sp { flex: 1; } .door .acts .meta { font: 11.5px var(--mono); color: var(--ink-3); }
  .door .alt.quiet { color: var(--ink-3); border-color: transparent; }
  .door .codes { margin-top: 24px; display: grid; grid-template-columns: repeat(5, 1fr); gap: 18px 24px; }
  .door .codes div { font: 500 18px var(--mono); color: var(--ink); letter-spacing: .04em; padding: 10px 0; }
  .door .codes div small { display: block; font: 10px var(--mono); color: var(--ink-3); letter-spacing: .1em; margin-bottom: 6px; }
  .door .two { display: grid; grid-template-columns: auto 1fr; gap: 40px; margin-top: 24px; align-items: start; }
  .door .qr { display: block; background: #fff; padding: 10px; border-radius: 6px; } .door .qr rect { fill: #06080e; }
  .door .qrcap { margin-top: 8px; font: 11px/1.45 var(--sans); color: var(--ink-3); text-align: center; }
  .door .wait { margin-top: 20px; display: flex; align-items: baseline; gap: 16px; }
  .door .wait b { font: 300 52px/1 var(--mono); color: var(--ink); letter-spacing: -.02em; } .door .wait span { font: 13px var(--sans); color: var(--ink-2); }
  .door .log { margin-top: 16px; font: 12px var(--mono); color: var(--ink-3); padding: 8px 12px; border-left: 2px solid var(--hair-2); }
  .door .log b { color: var(--ink); font-weight: 600; }
"""

# ---------------------------------------------------------------- the glass (round 9's S, carried; the barred "cage" pane is gone)
GLASS = CONTENT + """
  .g .floor { position: absolute; left: 0; right: 0; bottom: 0; height: 260px; background: linear-gradient(to top, rgba(157,184,232,.06), transparent); pointer-events: none; }
  .g .beam { position: absolute; right: 0; top: 180px; width: 900px; height: 540px; background: linear-gradient(270deg, rgba(157,184,232,.10), rgba(157,184,232,.03) 40%, transparent 75%); clip-path: polygon(100% 0, 100% 100%, 0 78%, 0 22%); opacity: .9; pointer-events: none; filter: blur(28px); }
  .g .pane { position: relative; height: 500px; width: 118px; border-radius: 14px; display: flex; align-items: center; justify-content: center;
    background: linear-gradient(160deg, rgba(160,185,230,.11), rgba(160,185,230,.02) 55%, rgba(160,185,230,.07)); backdrop-filter: blur(10px);
    box-shadow: inset 0 1px 0 rgba(255,255,255,.14), inset 0 -1px 0 rgba(0,0,0,.55), inset 1px 0 0 rgba(255,255,255,.05), 0 30px 60px -20px rgba(0,0,0,.75), 0 0 0 1px var(--hair-2); }
  .g .pane span { writing-mode: sideways-lr; font: 500 9.5px var(--mono); letter-spacing: .22em; text-transform: uppercase; color: var(--ink-3); white-space: nowrap; }
  .g .pane.done { transform: rotateY(50deg); transform-origin: left center; box-shadow: inset 0 1px 0 rgba(255,255,255,.14), inset 0 -1px 0 rgba(0,0,0,.55), 0 30px 60px -20px rgba(0,0,0,.75), 0 0 0 1px rgba(55,179,100,.6), 0 0 48px -8px rgba(55,179,100,.35); }
  .g .pane.done span { color: var(--ok); }
  .g .pane.done::before { content: '✓'; position: absolute; top: 14px; left: 0; right: 0; text-align: center; font: 700 12px var(--mono); color: var(--ok); }
  .g .pane.done::after { content: ''; position: absolute; left: -1px; top: 0; bottom: 0; width: 2px; background: linear-gradient(to bottom, transparent, rgba(55,179,100,.9), transparent); }
  .g .pane.ahead { transform: rotateY(-46deg); transform-origin: right center; box-shadow: inset 0 1px 0 rgba(255,255,255,.08), 0 30px 60px -20px rgba(0,0,0,.7); border: 1px dashed var(--hair-2); background: linear-gradient(160deg, rgba(160,185,230,.05), transparent 60%); }
  .g .door { width: 760px; min-height: 440px; border-radius: 18px; padding: 48px 56px 42px; position: relative; display: flex; flex-direction: column; isolation: isolate;
    background: linear-gradient(155deg, rgba(160,185,230,.12), rgba(160,185,230,.04) 38%, rgba(160,185,230,.025) 68%, rgba(160,185,230,.08)); backdrop-filter: blur(18px) saturate(1.3);
    box-shadow: inset 0 1px 0 rgba(255,255,255,.2), inset 0 -1px 0 rgba(0,0,0,.65), inset 1px 0 0 rgba(255,255,255,.08), inset -1px 0 0 rgba(0,0,0,.35), 0 50px 90px -30px rgba(0,0,0,.9), 0 0 0 1px rgba(157,184,232,.4), 0 0 80px -30px rgba(157,184,232,.25); }
  .g .door.wide { width: 880px; } .g .door.tall { min-height: 560px; }
  .g .door::before { content: ''; position: absolute; inset: 0; border-radius: inherit; z-index: -1; pointer-events: none;
    background: linear-gradient(112deg, rgba(255,255,255,.11) 0%, rgba(255,255,255,0) 30%), linear-gradient(292deg, rgba(255,255,255,.05), transparent 32%); }
  .g .door::after { content: ''; position: absolute; inset: 0; border-radius: inherit; z-index: -1; pointer-events: none; background: """ + NOISE + """; opacity: .045; mix-blend-mode: screen; }
  .g .door h2 { margin: 14px 0 10px; font: 300 38px/1.12 var(--sans); letter-spacing: -.015em; color: var(--ink); text-shadow: 0 2px 24px rgba(157,184,232,.25); }
  .g .door h2 b { font-weight: 600; }
  .g .door .fld .box { border-radius: 10px; padding: 0 16px; background: rgba(6,8,14,.38); box-shadow: inset 0 1px 3px rgba(0,0,0,.65), inset 0 -1px 0 rgba(255,255,255,.04), 0 0 0 1px var(--hair); }
  .g .door .fld.live .box { box-shadow: inset 0 1px 3px rgba(0,0,0,.65), inset 0 -1px 0 rgba(255,255,255,.04), 0 0 0 1px var(--accent), 0 0 22px -4px rgba(157,184,232,.55); }
  .g .door .fld.set .box { background: none; box-shadow: none; padding: 0; } .g .door .fld.set .box .key { font-size: 16px; letter-spacing: .05em; }
  .g .door .fld.off .box { box-shadow: 0 0 0 1px transparent; outline: 1px dashed var(--ink-3); outline-offset: -1px; background: rgba(6,8,14,.2); }
  .g .door .go { font: 600 14px var(--sans); color: var(--void); border-radius: 999px; padding: 12px 26px; background: linear-gradient(180deg, #bcd0f3, #93afe3);
    box-shadow: inset 0 1px 0 rgba(255,255,255,.55), inset 0 -1px 0 rgba(0,0,0,.15), 0 10px 28px -8px rgba(157,184,232,.75); }
  .g .door .go.off { background: rgba(6,8,14,.3); color: var(--ink-3); box-shadow: none; outline: 1px dashed var(--ink-3); }
  .g .door .alt { font: 600 12px var(--sans); color: var(--accent); border-radius: 999px; padding: 8px 16px; background: rgba(157,184,232,.07); box-shadow: inset 0 1px 0 rgba(255,255,255,.1), 0 0 0 1px var(--hair-2); white-space: nowrap; }
  .g .door .alt.quiet { background: none; box-shadow: none; }
  .g .door .codes div { border-top: 1px solid rgba(255,255,255,.1); box-shadow: 0 -1px 0 rgba(0,0,0,.5); }
  .g .door .log { background: rgba(6,8,14,.3); border-radius: 0 8px 8px 0; }
  /* refused: the glass frosts, the outline goes to ink, a line is etched on the pane */
  .g .door.refused { backdrop-filter: blur(30px); box-shadow: inset 0 1px 0 rgba(255,255,255,.2), inset 0 -1px 0 rgba(0,0,0,.65), 0 50px 90px -30px rgba(0,0,0,.9), 0 0 0 1px var(--ink); }
  .g .door.refused::after { opacity: .14; } .g .door.refused::before { background: linear-gradient(112deg, rgba(255,255,255,.14) 0%, rgba(255,255,255,.03) 40%, rgba(255,255,255,.06)); }
  .g .door .said { margin-top: 20px; font: 600 14px var(--sans); color: var(--ink); padding: 12px 16px; border-left: 2px solid var(--ink); background: rgba(233,238,251,.045); border-radius: 0 8px 8px 0; text-shadow: 0 1px 0 rgba(0,0,0,.6); }
  .g .door .said span { color: var(--ink-2); font-weight: 400; }
  /* too many tries: a shutter is down behind the glass; the outline is dashed like a silent canary's tile */
  .g .door.locked { background: linear-gradient(155deg, rgba(6,8,14,.55), rgba(6,8,14,.35)), repeating-linear-gradient(180deg, rgba(255,255,255,.035) 0 1px, transparent 1px 11px); backdrop-filter: blur(6px);
    box-shadow: inset 0 1px 0 rgba(255,255,255,.08), 0 50px 90px -30px rgba(0,0,0,.9); outline: 1px dashed var(--ink-3); outline-offset: -1px; }
  .g .door.locked::before { background: none; }
  @media (prefers-reduced-motion: no-preference) {
    .g .door { animation: g-arrive .7s cubic-bezier(.2,.7,.2,1) both; }
    @keyframes g-arrive { from { opacity: 0; transform: translateZ(-420px) rotateY(-22deg); } }
    .g .door.refused { animation: g-arrive .7s both, g-shake .5s .7s ease-in-out; }
    @keyframes g-shake { 20%, 60% { transform: translateX(-5px); } 40%, 80% { transform: translateX(5px); } }
  }
"""


class Glass:
    letter = name = ''
    qr = 196

    def door(self, step, h2, sub, inner, a, cls=''):
        return f'<div class="door {cls}"><div class="step">{step}</div><h2>{h2}</h2><div class="sub">{sub}</div>{inner}{a}</div>'

    def log(self, t):
        return f'<div class="log">{t}</div>'

    def two(self, qr, fields):
        return f'<div class="two"><div>{qr}<div class="qrcap">Scan with an authenticator app</div></div><div>{fields}</div></div>'

    def codes(self):
        return '<div class="codes">' + ''.join(f'<div><small>{i+1:02d}</small>{c}</div>' for i, c in enumerate(RECOVERY)) + '</div>'

    def wait(self, big, t):
        return f'<div class="wait"><b>{big}</b><span>{t}</span></div>'

    def said(self, t, note):
        return f'<div class="said">{t} <span>· {note}</span></div>'

    @staticmethod
    def panes(passed, ahead, extra=''):
        p = ''.join(f'<div class="pane done" style="--i:{i}" aria-label="passed: {html.escape(t)}"><span>{t}</span></div>' for i, t in enumerate(passed))
        n = len(ahead)
        a = ''.join(f'<div class="pane ahead" style="--j:{n-1-j}" aria-label="ahead: {html.escape(t)}"><span>{t}</span></div>' for j, t in enumerate(ahead))
        return p, a


# ================================================================ V · the column
# The door stands where the trace will: across the band's column, X0 to X1. The doors you have
# passed fold into the gutter where the lane labels sit; the doors ahead stand in the deck's
# column at the right edge, in the deck's type, where "the trace" will read.
# When the last door swings away, the four lines run across the glass's footprint.
V_CSS = GLASS + """
  .v { background: radial-gradient(900px 600px at 86% 42%, rgba(157,184,232,.09), transparent 62%), radial-gradient(1200px 500px at 20% 110%, rgba(80,115,205,.05), transparent 60%), var(--void); }
  .v .hall { position: absolute; inset: 0; perspective: 1600px; perspective-origin: 50% 44%; }
  .v .hall > * { position: absolute; }
  .v .hall::after { content: ''; position: absolute; left: 190px; width: 1180px; bottom: 150px; height: 140px; background: radial-gradient(ellipse at 50% 0, rgba(157,184,232,.14), transparent 70%); filter: blur(10px); pointer-events: none; }
  .v .door { left: 190px; top: 198px; width: 1178px; min-height: 470px; padding: 44px 56px 40px; }
  .v .door.wide { width: 1178px; } .v .door.tall { top: 150px; min-height: 580px; width: 1096px; }
  .v .door .fields { max-width: 820px; } .v .door .fields.wide { max-width: 760px; }
  .v .door .two { grid-template-columns: auto 760px; }
  .v .door .codes { max-width: 1000px; }
  .v .door .acts { max-width: 1000px; }
  .v .pane { top: 198px; height: 470px; width: 118px; }
  .v .door.tall ~ .pane, .v .hall.firstrun .pane { top: 150px; height: 580px; }
  .v .pane.done { left: calc(54px + var(--i) * 38px); transform: rotateY(64deg); z-index: 1; }
  .v .pane.ahead { right: calc(12px + var(--j) * 56px); transform: rotateY(-66deg); }
  .v .hall.timeout .pane.done { left: 54px; }
  .v .beam { right: 0; width: 700px; top: 160px; }
"""


class V(Glass):
    letter, name = 'v', 'the column'

    def hall(self, passed, d, ahead, kind):
        p, a = self.panes(passed, ahead)
        extra = '' if kind == 'timeout' else '<div class="floor" aria-hidden="true"></div><div class="beam" aria-hidden="true"></div>'
        return f'{extra}<div class="hall {kind}" aria-label="the doors">{p}{d}{a}</div>'


# ================================================================ W · the brink
# The one thing the door and the cage share is the brink: the trace's amber line of now, standing
# at the right of the room exactly where it stands on the band, with the band's own label under
# it. The doors stand on the stretched quarter hour; beyond the brink is the lit page. When the
# last door swings away the brink has not moved; the lines draw across to meet it.
W_CSS = GLASS + """
  .w { background: radial-gradient(900px 600px at 95% 45%, rgba(157,184,232,.10), transparent 62%), radial-gradient(1200px 500px at 20% 110%, rgba(80,115,205,.05), transparent 60%), var(--void); }
  .w .hall { position: absolute; left: 0; right: 92px; top: 130px; height: 580px; display: flex; justify-content: center; align-items: center; gap: 22px; perspective: 1500px; perspective-origin: 50% 46%; }
  .w .hall::after { content: ''; position: absolute; left: 50%; bottom: -60px; width: 980px; height: 140px; transform: translateX(-50%); background: radial-gradient(ellipse at 50% 0, rgba(157,184,232,.16), transparent 70%); filter: blur(10px); pointer-events: none; }
  .w .hall.timeout { justify-content: flex-start; padding-left: 190px; top: 190px; } .w .hall.timeout .door { width: 640px; } .w .hall.timeout .pane { backdrop-filter: blur(14px); }
  .w .hall.timeout .pane.done { position: absolute; left: 60px; }
  .w .brink { position: absolute; left: 1368px; top: 150px; width: 1.6px; height: 596px; background: var(--now); box-shadow: 0 0 18px -2px rgba(232,176,90,.45); z-index: 4; }
  .w .brink::before { content: ''; position: absolute; left: -200px; top: 0; bottom: 0; width: 200px; background: linear-gradient(90deg, transparent, rgba(232,176,90,.035)); pointer-events: none; }
  .w .nowlab { position: absolute; left: 1150px; width: 218px; top: 756px; text-align: right; font: 600 9.5px var(--mono); letter-spacing: .12em; color: var(--now); text-transform: uppercase; z-index: 4; }
  .w .axis { position: absolute; left: 120px; width: 1248px; top: 744px; height: 1px; background: var(--hair-2); z-index: 4; }
  .w .axis i { position: absolute; top: -6px; width: 1px; height: 6px; background: var(--hair-2); }
  .w .axis em { position: absolute; left: 0; top: 12px; font: 600 9.5px var(--mono); letter-spacing: .12em; color: var(--ink-3); font-style: normal; }
  .w .axis small { position: absolute; left: 50%; transform: translateX(-50%); top: 12px; font: 9.5px var(--sans); color: var(--ink-3); opacity: .8; white-space: nowrap; }
  .w .beam { right: 0; width: 640px; top: 140px; height: 620px; clip-path: polygon(100% 0, 100% 100%, 0 82%, 0 18%); }
  .w .hall.timeout ~ .axis, .w .hall.timeout ~ .nowlab, .w .hall.timeout ~ .brink::before { display: none; }
"""


class W(Glass):
    letter, name = 'w', 'the brink'

    def hall(self, passed, d, ahead, kind):
        p, a = self.panes(passed, ahead)
        extra = '' if kind == 'timeout' else '<div class="floor" aria-hidden="true"></div><div class="beam" aria-hidden="true"></div>'
        ticks = ''.join(f'<i style="left:{x}px"></i>' for x in range(0, 1249, 52))
        axis = '' if kind == 'timeout' else f'<div class="axis" aria-hidden="true">{ticks}<em>15 M</em><small>the last quarter hour, stretched</small></div>'
        brink = f'<div class="brink" aria-hidden="true"></div><div class="nowlab" aria-label="now">NOW · {TIMES[kind]}</div>'
        return f'{extra}<div class="hall {kind}" aria-label="the doors">{p}{d}{a}</div>{axis}{brink}'


# ================================================================ X · through the frost
# What is behind the glass is the cage: not its data, its light. The shell's lit surfaces -- the
# heading, the band, the four tiles -- lie behind every door as soft luminance in the shell's own
# places, seen through the frost. No text, no lane colour, no mark: the shape is the shell at
# rest, the same for every installation. The frost thins door by door, and the last door
# opening is the frost clearing.
X_CSS = GLASS + """
  .x { background: radial-gradient(1200px 500px at 20% 110%, rgba(80,115,205,.04), transparent 60%), var(--void); }
  .x .wall { position: absolute; inset: 0; pointer-events: none; --lit: .5; }
  .x .wall i { position: absolute; display: block; border-radius: 10px; background: rgba(160,185,230,calc(.11 * var(--lit))); filter: blur(26px); }
  .x .wall .hd { left: 54px; top: 92px; width: 400px; height: 34px; border-radius: 17px; background: rgba(160,185,230,calc(.20 * var(--lit))); }
  .x .wall .sb { left: 54px; top: 140px; width: 820px; height: 40px; background: rgba(160,185,230,calc(.05 * var(--lit))); }
  .x .wall .bd { left: 190px; top: 294px; width: 1178px; height: 48px; border-radius: 24px; background: rgba(160,185,230,calc(.15 * var(--lit))); filter: blur(18px); }
  .x .wall .bk { left: 1364px; top: 200px; width: 7px; height: 174px; border-radius: 4px; background: rgba(232,176,90,calc(.34 * var(--lit))); filter: blur(7px); }
  .x .wall .tl { top: 470px; width: 318px; height: 96px; }
  .x .hall { position: absolute; left: 0; right: 0; top: 130px; height: 580px; display: flex; justify-content: center; align-items: center; gap: 22px; perspective: 1500px; perspective-origin: 50% 46%; }
  .x .hall::after { content: ''; position: absolute; left: 50%; bottom: -60px; width: 980px; height: 140px; transform: translateX(-50%); background: radial-gradient(ellipse at 50% 0, rgba(157,184,232,.14), transparent 70%); filter: blur(10px); pointer-events: none; }
  .x .door { backdrop-filter: blur(calc(28px - 14px * var(--lit, .5))) saturate(1.3); }
  .x .pane { backdrop-filter: blur(14px); }
  .x .pane.ahead { background: linear-gradient(160deg, rgba(160,185,230,.08), rgba(160,185,230,.02) 60%); }
  .x .hall.timeout { justify-content: flex-start; padding-left: 190px; top: 190px; } .x .hall.timeout .door { width: 640px; }
  .x .hall.timeout .pane.done { position: absolute; left: 60px; }
"""


class X(Glass):
    letter, name = 'x', 'through the frost'

    def hall(self, passed, d, ahead, kind):
        p, a = self.panes(passed, ahead)
        if kind == 'timeout':
            return f'<div class="hall {kind}" aria-label="the doors">{p}{d}{a}</div>'
        total = len(passed) + 1 + len(ahead)
        lit = .45 + .55 * (len(passed) + 1) / total
        tiles = ''.join(f'<i class="tl" style="left:{54 + k*332}px"></i>' for k in range(4))
        wall = f'<div class="wall" style="--lit:{lit:.2f}" aria-hidden="true"><i class="hd"></i><i class="sb"></i><i class="bd"></i><i class="bk"></i>{tiles}</div>'
        d = d.replace('class="door ', f'class="door " style="--lit:{lit:.2f}" data-x="', 1).replace('" data-x="', ' ', 1) if False else d.replace('<div class="door ', f'<div style="--lit:{lit:.2f}" class="door ', 1)
        return f'{wall}<div class="floor" aria-hidden="true"></div><div class="hall {kind}" aria-label="the doors">{p}{d}{a}</div>'


# ---------------------------------------------------------------- motion pages
# One 12 s loop: door one swings away on its hinge, door two arrives out of the depth and is
# passed, then the hand-over: the last glass goes and the real shell's first view is there.
MOTION_BASE = """
  .stage { position: relative; width: 1440px; height: 900px; margin: 0 auto; overflow: hidden; background: var(--void); }
  .stage .cap { position: absolute; left: 50%; transform: translateX(-50%); bottom: 16px; white-space: nowrap; padding: 6px 14px; border-radius: 999px; background: var(--void); text-align: center; font: 12.5px var(--sans); color: var(--ink-2); z-index: 8; }
  .stage .still { position: absolute; top: 18px; left: 50%; transform: translateX(-50%); font: 10px var(--mono); letter-spacing: .14em; text-transform: uppercase; color: var(--ink-3); z-index: 5; }
  .stage .shell.into { opacity: 0; z-index: 6; background: var(--void); }
  .stage .shell.into svg.band { clip-path: inset(0 0 0 0); }
  @media (prefers-reduced-motion: no-preference) {
    .stage .still { display: none; }
    .stage .shell.into { animation: m-shell 12s infinite; } @keyframes m-shell { 0%, 64% { opacity: 0; } 74%, 94% { opacity: 1; } 100% { opacity: 0; } }
    .stage .shell.into svg.band { animation: m-lines 12s cubic-bezier(.4,0,.2,1) infinite; } @keyframes m-lines { 0%, 68% { clip-path: inset(0 100% 0 0); } 84%, 100% { clip-path: inset(0 0 0 0); } }
    .stage .chrome { animation: m-chrome 12s infinite; } @keyframes m-chrome { 0%, 66% { opacity: 1; } 72%, 94% { opacity: 0; } 100% { opacity: 1; } }
  }
"""


def motion_page(D, css, body, cap, shell_cls=''):
    return page(f'Birdcage · round 10 · {D.letter.upper()} · {D.name} · motion',
                css + MOTION_BASE,
                f'<div class="stage g {D.letter}" role="region" aria-label="{D.letter.upper()}, {D.name}: the motion, door to door, then the hand-over into the cage">'
                f'<div class="still">reduced motion · still</div><div class="chrome">{chrome()}</div>{body}'
                f'{shell("09:18:12", cls="into " + shell_cls)}'
                f'<div class="cap">{cap}</div></div>')


def door_one(D):
    return D.door(f'sign in · step 1 of 2 · {DAY} · {NOW}', 'Sign in', f'Connecting from <span class="ip">{IP}</span>.',
                  '<div class="fields">' + fld('username', 'ada', 'live') + fld('password', '<span>••••••••••••</span>', 'live') + '</div>',
                  acts('Sign in', [('Use a passkey', ''), ('Sign in with SSO', 'quiet')]))


def door_two(D):
    return D.door(f'sign in · step 2 of 2 · {DAY} · 09:18:09', 'Enter your authentication code',
                  'Enter the six-digit code from your authenticator app.',
                  '<div class="fields one">' + fld('authentication code', '<span class="digits">417 926</span>', 'live', 'accepted') + '</div>',
                  acts('Continue', [('Use a recovery code', 'quiet')], 'Last sign-in: Thu 13 Nov, 09:41'))


# the hinge: the same keyframes in all three; only where things stand differs
HINGE = """
  @media (prefers-reduced-motion: no-preference) {
    .m .d1 { animation: m-d1 12s cubic-bezier(.4,0,.2,1) infinite; }
    @keyframes m-d1 { 0% { opacity: 0; transform: translateZ(-420px) rotateY(-22deg); } 6%, 22% { opacity: 1; transform: none; } 30%, 100% { opacity: 0; transform: rotateY(-82deg); } }
    .m .p1 { animation: m-p1 12s infinite; } @keyframes m-p1 { 0%, 28% { opacity: 0; } 34%, 66% { opacity: 1; } 72%, 100% { opacity: 0; } }
    .m .p2 { animation: m-p2 12s infinite; } @keyframes m-p2 { 0%, 26% { opacity: 1; } 32%, 100% { opacity: 0; } }
    .m .d2 { animation: m-d2 12s cubic-bezier(.4,0,.2,1) infinite; }
    @keyframes m-d2 { 0%, 26% { opacity: 0; transform: translateX(var(--from, 640px)) translateZ(-700px) rotateY(-40deg); } 36%, 56% { opacity: 1; transform: none; } 64%, 100% { opacity: 0; transform: rotateY(-82deg); } }
    .m .room { animation: m-room 12s infinite; } @keyframes m-room { 0%, 62% { opacity: 1; } 72%, 94% { opacity: 0; } 100% { opacity: 1; } }
  }
"""

V_MOTION = HINGE + """
  .v .d1, .v .d2 { left: 190px; top: 198px; transform-origin: left center; } .v .d1 { opacity: 0; }
  .v .room { position: absolute; inset: 0; pointer-events: none; }
"""

W_MOTION = HINGE + """
  .w .hall > * { position: absolute; }
  .w .d1, .w .d2 { left: 50%; margin-left: -460px; top: 40px; transform-origin: left center; } .w .d1 { opacity: 0; }
  .w .p1 { left: 50%; margin-left: -600px; top: 40px; }
  .w .p2 { left: 50%; margin-left: 320px; top: 40px; }
  .w .room { position: absolute; inset: 0; pointer-events: none; }
  .w .brink, .w .nowlab { z-index: 7; }
  .w .nowlab { font-variant-numeric: tabular-nums; }
  .stage.w .shell.into .ax.now { opacity: 0; }
  .w .nowlab b { font-weight: inherit; }
  @media (prefers-reduced-motion: no-preference) {
    .w .nowlab { animation: m-nowlab 12s infinite; } @keyframes m-nowlab { 0%, 68% { top: 756px; } 74%, 100% { top: 382px; } }
    .w .brink { animation: m-brink 12s infinite; } @keyframes m-brink { 0%, 68% { top: 150px; height: 596px; } 74%, 100% { top: 200px; height: 174px; } }
    .w .nowlab .t1 { animation: m-t1 12s infinite; } .w .nowlab .t2 { animation: m-t2 12s infinite; }
    @keyframes m-t1 { 0%, 60% { opacity: 1; } 61%, 100% { opacity: 0; } } @keyframes m-t2 { 0%, 60% { opacity: 0; } 61%, 100% { opacity: 1; } }
  }
  .w .nowlab .t2 { position: absolute; right: 0; top: 0; opacity: 0; }
"""

X_MOTION = HINGE + """
  .x .hall > * { position: absolute; }
  .x .d1, .x .d2 { left: 50%; margin-left: -380px; top: 40px; transform-origin: left center; } .x .d1 { opacity: 0; }
  .x .p1 { left: 50%; margin-left: -520px; top: 40px; }
  .x .p2 { left: 50%; margin-left: 400px; top: 40px; }
  .x .room { position: absolute; inset: 0; pointer-events: none; }
  .x .wall { --lit: .75; }
  .stage.x .shell.into { background: transparent; }
  @media (prefers-reduced-motion: no-preference) {
    .x .wall { animation: m-wall 12s infinite; } @keyframes m-wall { 0%, 30% { --lit: .75; } 36%, 60% { --lit: 1; } 64%, 100% { --lit: 1; } }
    .x .wall i { animation: m-focus 12s cubic-bezier(.4,0,.2,1) infinite; } @keyframes m-focus { 0%, 62% { filter: blur(22px); opacity: 1; } 74% { filter: blur(0px); opacity: 1; } 80%, 94% { filter: blur(0px); opacity: 0; } 100% { filter: blur(22px); opacity: 1; } }
  }
"""


def build_motion(D):
    L = D.letter
    d1 = door_one(D).replace('class="door ', 'class="door d1 ', 1)
    d2 = door_two(D).replace('class="door ', 'class="door d2 ', 1)
    p1 = '<div class="pane done p1" style="--i:0" aria-label="passed: password"><span>Password</span></div>'
    p2 = '<div class="pane ahead p2" style="--j:0" aria-label="ahead: authentication code"><span>Authentication code</span></div>'
    if L == 'v':
        body = ('<div class="room"><div class="floor" aria-hidden="true"></div><div class="beam" aria-hidden="true"></div></div>'
                f'<div class="hall m" aria-label="the doors">{p1}{d1}{d2}{p2}</div>')
        cap = 'V · the column · motion'
        return motion_page(D, V_CSS + V_MOTION, body, cap)
    if L == 'w':
        ticks = ''.join(f'<i style="left:{x}px"></i>' for x in range(0, 1249, 52))
        body = ('<div class="room"><div class="floor" aria-hidden="true"></div><div class="beam" aria-hidden="true"></div>'
                f'<div class="axis" aria-hidden="true">{ticks}<em>15 M</em><small>the last quarter hour, stretched</small></div></div>'
                f'<div class="hall m" aria-label="the doors">{p1}{d1}{d2}{p2}</div>'
                '<div class="brink" aria-hidden="true"></div><div class="nowlab" aria-label="now"><span class="t1">NOW · 09:18:09</span><span class="t2">NOW · 09:18:12</span></div>')
        cap = 'W · the brink · motion'
        return motion_page(D, W_CSS + W_MOTION, body, cap)
    tiles = ''.join(f'<i class="tl" style="left:{54 + k*332}px"></i>' for k in range(4))
    body = (f'<div class="wall" aria-hidden="true"><i class="hd"></i><i class="sb"></i><i class="bd"></i><i class="bk"></i>{tiles}</div>'
            '<div class="room"><div class="floor" aria-hidden="true"></div></div>'
            f'<div class="hall m" aria-label="the doors">{p1}{d1}{d2}{p2}</div>')
    cap = 'X · through the frost · motion'
    return motion_page(D, X_CSS + X_MOTION, body, cap)


def build_dir(D, css):
    return page(f'Birdcage · round 10 · {D.letter.upper()} · {D.name}', css, '\n\n'.join(scenes_for(D)))


if __name__ == '__main__':
    for D, css in [(V(), V_CSS), (W(), W_CSS), (X(), X_CSS)]:
        fn = dict((l, f) for l, _, f in DIRS)[D.letter]
        with open(fn, 'w') as f:
            f.write(build_dir(D, css))
        print(fn)
        mf = f'motion-{D.letter}.html'
        with open(mf, 'w') as f:
            f.write(build_motion(D))
        print(mf)
