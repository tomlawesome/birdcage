#!/usr/bin/env python3
"""Round 9: the doors, developed (#8, slice B). Round 8's R carried forward and drawn
three ways, each a different answer to "what are these doors made of and how do they
move": S smoked glass, T slate and ink, U wire gates. Same copy, data and eight scenes
in every direction; palette, type roots and chrome are round 6/7's, copied so the round
stands alone.
Run here: python3 gen.py  ->  direction-{s,t,u}-*.html, motion-{s,t,u}.html"""
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
SCENES = [('signin', 'sign in'), ('factor', 'second factor'), ('firstrun', 'first run'),
          ('enrol', 'enrol an authenticator'), ('codes', 'recovery codes, shown once'),
          ('timeout', 'timed out'), ('refused', 'refused'), ('locked', 'too many tries')]
DIRS = [('s', 'smoked glass', 'direction-s-smoked-glass.html'),
        ('t', 'slate and ink', 'direction-t-slate-and-ink.html'),
        ('u', 'wire gates', 'direction-u-wire-gates.html')]

# paper grain / frosted glass: one tiny SVG, never animated
NOISE = ("url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='180' height='180'%3E"
         "%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.85' numOctaves='3' stitchTiles='stitch'/%3E"
         "%3CfeColorMatrix values='0 0 0 0 1 0 0 0 0 1 0 0 0 0 1 0 0 0 .6 0'/%3E%3C/filter%3E"
         "%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E\")")
# a harsher grain for the rubber stamp's ink
GRIT = ("url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='160' height='160'%3E"
        "%3Cfilter id='g'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.55' numOctaves='2' stitchTiles='stitch'/%3E"
        "%3CfeColorMatrix values='0 0 0 0 1 0 0 0 0 1 0 0 0 0 1 0 0 0 2.6 -.5'/%3E%3C/filter%3E"
        "%3Crect width='100%25' height='100%25' filter='url(%23g)'/%3E%3C/svg%3E\")")


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
    --serif: Charter, "Bitstream Charter", "Iowan Old Style", "Palatino Linotype", Palatino, Georgia, serif;
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
  .behind .bfoot { position: absolute; left: 0; right: 40px; bottom: 14px; text-align: center; font: 12.5px var(--sans); color: var(--ink-2); }
  .scrim { position: absolute; inset: 0; background: rgba(6,8,14,.72); }
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
            '<div class="bfoot">fourteen quiet days · nothing to act on</div>'
            '</div><div class="scrim"></div>')


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
# Every direction draws these; only the door, its hall and its motion differ.
def scenes_for(D):
    """D: a direction with door(step,h2,sub,inner,acts,cls), hall(passed, door, ahead, cls),
    said(text,note), log(text), two(qr,fields), codes(), wait(big,text), letter, name."""
    S = []
    L, N = D.letter, D.name
    tag = lambda i: f'{L.upper()} · {N} · scene {i} · {SCENES[i-1][1]}'
    sid = lambda k: f'{L}-{k}'

    # 1 sign in
    d = D.door(f'the door · {DAY} · {NOW}', 'Say who you are.',
               f'Birdcage is watching four canaries. Nothing they have seen is shown until you are through. You are <span class="ip">{IP}</span>.',
               '<div class="fields">' + fld('who', inp('user', 'ada', 'username'), 'live') + fld('password', inp('pass', '', 'password', 'password', live=True), 'live') + '</div>',
               acts('sign in ▸', [('use a passkey', ''), ('sign in with SSO', 'quiet')], 'then a code, then the cage'))
    body = chrome() + D.hall([], d, ['a code'], 'signin') + foot(f'birdcage {VER} · each door you pass folds to the left; the ones ahead wait on the right, the cage last')
    S.append(scene(sid('signin'), f'{L.upper()}, {N}: sign in', body, tag(1), L))

    # 2 second factor
    d = D.door(f'the door · {DAY} · 09:18:09 · second of three', '<b>ada</b>, one more thing.',
               'A code from your authenticator app: six digits, a new one every thirty seconds. If the phone is gone, a recovery code opens this door once.',
               '<div class="fields one">' + fld('code', DIGITS_417, 'live', 'this one is good for another 19 s') + '</div>',
               acts('continue ▸', [('use a recovery code instead', 'quiet')], 'ada last signed in thu 13 nov 09:41'))
    body = chrome() + D.hall(['ada · password'], d, [], 'factor') + foot(f'birdcage {VER} · password accepted 09:18:09 · a session ends after an hour unused, and after a day whatever happens')
    S.append(scene(sid('factor'), f'{L.upper()}, {N}: second factor', body, tag(2), L))

    # 3 first run
    d = D.door(f'first run · {DAY} · {NOW} · first of four', 'No one has keys yet.',
               f'Birdcage {VER} started at 09:12 with no accounts and printed a setup code in its server log. Paste it, then name the first admin. The code is good for fifteen minutes, once.',
               D.log(f'09:12:04 birdcage {VER} · no accounts · <b>setup code {SETUP}</b> · valid until 09:27')
               + '<div class="fields">' + fld('setup code', f'<span class="mono">{SETUP}</span>', 'live', 'from the server log')
               + fld('first admin', inp('user', 'ada', 'username for the first admin'), 'live', 'lower-case letters, digits, dots and dashes')
               + fld('password', inp('pass', '••••••••••••••', 'password', 'password'), 'live', 'twelve characters or more; a phrase is fine')
               + fld('again', inp('pass2', '•••••••', 'password, again', 'password', live=True), 'live') + '</div>',
               acts('create the first admin ▸', [('sign in with SSO instead', 'quiet')], 'then an authenticator, then recovery codes'), 'tall')
    body = chrome() + D.hall([], d, ['an authenticator', 'recovery codes'], 'firstrun') + foot(f'birdcage {VER} · until an admin exists the cage shows nothing and answers 503')
    S.append(scene(sid('firstrun'), f'{L.upper()}, {N}: first run', body, tag(3), L))

    # 4 enrol
    inner = D.two(qr_svg(D.qr), '<div class="fields one wide">'
                  + fld('or type the key', f'<span class="mono key">{KEY}</span>', 'set', 'account birdcage:ada · time-based · 6 digits · 30 s')
                  + fld('the first code the app shows', DIGITS_NONE, 'live') + '</div>')
    d = D.door(f'first run · {DAY} · 09:18:14 · second of four', 'Now a second thing you hold.',
               'Every password account carries a second factor. Scan the square or type the key into an authenticator app, then prove it with one code. A passkey can be added later.',
               inner, acts('confirm ▸', [], 'the key is shown once'), 'wide')
    body = chrome() + D.hall(['setup code', 'ada · admin'], d, ['recovery codes'], 'enrol') + foot(f'birdcage {VER} · if the app loses the key, an admin resets it from the users page')
    S.append(scene(sid('enrol'), f'{L.upper()}, {N}: enrol an authenticator', body, tag(4), L))

    # 5 recovery codes
    d = D.door(f'first run · {DAY} · 09:18:41 · third of four', 'Ten recovery codes. <b>Shown once.</b>',
               'Each opens the door one time if the phone is gone. Keep them somewhere that is not this computer: a password manager, or paper. Birdcage never shows them again; an admin can issue ten more.',
               D.codes(), acts('I have kept them · go in ▸', [('copy', ''), ('download as text', ''), ('print', 'quiet')], '10 of 10 unused'), 'wide')
    body = chrome() + D.hall(['setup code', 'ada · admin', 'authenticator'], d, [], 'codes') + foot(f'birdcage {VER} · the last door before the cage')
    S.append(scene(sid('codes'), f'{L.upper()}, {N}: recovery codes shown once', body, tag(5), L))

    # 6 timed out (ADR-0016 §6: an hour unused ends the session; a day ends it whatever happens;
    # within the day the password alone carries on, no second factor; owner answer 5a)
    d = D.door(f'the door · {DAY} · {NOW} · session ended', '<b>ada</b>, you were away.',
               'You signed in at 07:31 and last touched the dashboard at 07:52; an hour unused ended the session at 08:52, so what is behind this door is <b>26 minutes</b> behind. '
               'Your password alone carries on from where you were. The full sign-in, second factor and all, is due again by <b>Sunday 07:31</b>.',
               '<div class="fields one">' + fld('password', inp('pass', '', 'password', 'password', live=True), 'live', 'no second factor until the day is up · a passkey also carries on') + '</div>',
               acts('carry on ▸', [('sign in as someone else', 'quiet')], 'nothing is lost'))
    body = behind() + D.hall(['ada · signed in 07:31'], d, [], 'timeout')
    S.append(scene(sid('timeout'), f'{L.upper()}, {N}: timed out, a door over the dimmed dashboard', body, tag(6), L))

    # 7 refused
    d = D.door(f'the door · {DAY} · 09:18:07 · refused', 'That is not <b>ada</b>\'s password.',
               'Four more tries before a five-minute wait. Whether the name exists is not said.',
               '<div class="fields">' + fld('who', inp('user', 'ada', 'username'), 'live') + fld('password', inp('pass', '', 'password', 'password', live=True), 'live') + '</div>'
               + D.said('refused · 09:18:07', '4 tries left · the wait is per name and per address'),
               acts('try again ▸', [('use a passkey', ''), ('sign in with SSO', 'quiet')], '1 refusal in this five minutes'), 'refused')
    body = chrome() + D.hall([], d, ['a code'], 'refused') + foot(f'birdcage {VER} · a refusal is ink, never alarm: the door {D.refusal_words}')
    S.append(scene(sid('refused'), f'{L.upper()}, {N}: refused, wrong password', body, tag(7), L))

    # 8 too many tries
    d = D.door(f'the door · {DAY} · 09:18:48 · too many tries', 'Too many tries. <b>Wait.</b>',
               f'Five wrong passwords for <b>ada</b> from <span class="ip">{IP}</span> inside five minutes. The door opens again for this name from this address at <b>09:23:00</b>; anyone else, <b>wren</b> included, can still sign in.',
               D.wait('4:12', 'until it opens · counting down · the fields wake up when it does')
               + '<div class="fields">' + fld('who', 'ada', 'off') + fld('password', '', 'off', '5 refusals, 09:18:07 to 09:18:48 · all in the audit log') + '</div>',
               acts('sign in', [('use a passkey', ''), ('sign in with SSO', 'quiet')], 'a passkey or SSO is not counted', 'go off'), 'locked')
    body = chrome() + D.hall([], d, ['a code'], 'locked') + foot(f'birdcage {VER} · a closed door {D.locked_words}, the way the trace draws a silent canary')
    S.append(scene(sid('locked'), f'{L.upper()}, {N}: too many tries, wait', body, tag(8), L))
    return S


# ---------------------------------------------------------------- shared door-content css
# Fields, buttons, notes: the same skeleton, dressed by each direction below.
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


class Direction:
    letter = name = ''
    qr = 196
    refusal_words = ''
    locked_words = ''

    def log(self, t):
        return f'<div class="log">{t}</div>'

    def two(self, qr, fields):
        return f'<div class="two"><div>{qr}<div class="qrcap">scan with any authenticator app<br>(a placeholder pattern in this mock-up)</div></div><div>{fields}</div></div>'

    def codes(self):
        return '<div class="codes">' + ''.join(f'<div><small>{i+1:02d}</small>{c}</div>' for i, c in enumerate(RECOVERY)) + '</div>'

    def wait(self, big, t):
        return f'<div class="wait"><b>{big}</b><span>{t}</span></div>'

    def said(self, t, note):
        return f'<div class="said">{t} <span>· {note}</span></div>'


# ================================================================ S · smoked glass
S_CSS = CONTENT + """
  .s { background: radial-gradient(900px 600px at 82% 42%, rgba(157,184,232,.09), transparent 62%), radial-gradient(1200px 500px at 20% 110%, rgba(80,115,205,.05), transparent 60%), var(--void); }
  .s .floor { position: absolute; left: 0; right: 0; bottom: 0; height: 260px; background: linear-gradient(to top, rgba(157,184,232,.06), transparent); pointer-events: none; }
  .s .beam { position: absolute; right: 0; top: 180px; width: 900px; height: 540px; background: linear-gradient(270deg, rgba(157,184,232,.10), rgba(157,184,232,.03) 40%, transparent 75%); clip-path: polygon(100% 0, 100% 100%, 0 78%, 0 22%); opacity: .9; pointer-events: none; filter: blur(28px); }
  .s .hall { position: absolute; left: 0; right: 0; top: 140px; height: 580px; display: flex; justify-content: center; align-items: center; gap: 22px; perspective: 1500px; perspective-origin: 50% 46%; }
  .s .hall::after { content: ''; position: absolute; left: 50%; bottom: -60px; width: 980px; height: 140px; transform: translateX(-50%); background: radial-gradient(ellipse at 50% 0, rgba(157,184,232,.16), transparent 70%); filter: blur(10px); pointer-events: none; }
  .s .pane { position: relative; height: 500px; width: 118px; border-radius: 14px; display: flex; align-items: center; justify-content: center;
    background: linear-gradient(160deg, rgba(160,185,230,.11), rgba(160,185,230,.02) 55%, rgba(160,185,230,.07)); backdrop-filter: blur(10px);
    box-shadow: inset 0 1px 0 rgba(255,255,255,.14), inset 0 -1px 0 rgba(0,0,0,.55), inset 1px 0 0 rgba(255,255,255,.05), 0 30px 60px -20px rgba(0,0,0,.75), 0 0 0 1px var(--hair-2); }
  .s .pane span { writing-mode: sideways-lr; font: 600 11px var(--mono); letter-spacing: .22em; text-transform: uppercase; color: var(--ink-3); white-space: nowrap; }
  .s .pane.done { transform: rotateY(50deg); transform-origin: left center; box-shadow: inset 0 1px 0 rgba(255,255,255,.14), inset 0 -1px 0 rgba(0,0,0,.55), 0 30px 60px -20px rgba(0,0,0,.75), 0 0 0 1px rgba(55,179,100,.6), 0 0 48px -8px rgba(55,179,100,.35); }
  .s .pane.done span { color: var(--ok); }
  .s .pane.done::before { content: '✓'; position: absolute; top: 14px; left: 0; right: 0; text-align: center; font: 700 12px var(--mono); color: var(--ok); }
  .s .pane.done::after { content: ''; position: absolute; left: -1px; top: 0; bottom: 0; width: 2px; background: linear-gradient(to bottom, transparent, rgba(55,179,100,.9), transparent); }
  .s .pane.ahead { transform: rotateY(-46deg); transform-origin: right center; box-shadow: inset 0 1px 0 rgba(255,255,255,.08), 0 30px 60px -20px rgba(0,0,0,.7); border: 1px dashed var(--hair-2); background: linear-gradient(160deg, rgba(160,185,230,.05), transparent 60%); }
  .s .pane.cage { transform: rotateY(-32deg); transform-origin: right center; width: 112px; border: 0;
    background: repeating-linear-gradient(90deg, rgba(157,184,232,.75) 0 1px, transparent 1px 9px), radial-gradient(ellipse at 50% 60%, rgba(157,184,232,.35), rgba(157,184,232,.06) 70%);
    box-shadow: inset 0 1px 0 rgba(255,255,255,.2), 0 0 0 1px rgba(157,184,232,.55), 0 0 70px -10px rgba(157,184,232,.55), 0 30px 60px -20px rgba(0,0,0,.7); }
  .s .pane.cage span { color: var(--ink); text-shadow: 0 0 8px rgba(6,8,14,.9), 0 0 2px var(--void); background: rgba(6,8,14,.55); padding: 10px 4px; border-radius: 4px; }
  .s .door { width: 760px; min-height: 440px; border-radius: 18px; padding: 48px 56px 42px; position: relative; display: flex; flex-direction: column; isolation: isolate;
    background: linear-gradient(155deg, rgba(160,185,230,.12), rgba(160,185,230,.04) 38%, rgba(160,185,230,.025) 68%, rgba(160,185,230,.08)); backdrop-filter: blur(18px) saturate(1.3);
    box-shadow: inset 0 1px 0 rgba(255,255,255,.2), inset 0 -1px 0 rgba(0,0,0,.65), inset 1px 0 0 rgba(255,255,255,.08), inset -1px 0 0 rgba(0,0,0,.35), 0 50px 90px -30px rgba(0,0,0,.9), 0 0 0 1px rgba(157,184,232,.4), 0 0 80px -30px rgba(157,184,232,.25); }
  .s .door.wide { width: 880px; } .s .door.tall { min-height: 560px; }
  .s .hall:has(.door.wide) { gap: 16px; } .s .hall:has(.door.wide) .pane { width: 84px; } .s .hall:has(.door.wide) .pane.cage { width: 96px; }
  .s .door::before { content: ''; position: absolute; inset: 0; border-radius: inherit; z-index: -1; pointer-events: none;
    background: linear-gradient(112deg, rgba(255,255,255,.11) 0%, rgba(255,255,255,0) 30%), linear-gradient(292deg, rgba(255,255,255,.05), transparent 32%); }
  .s .door::after { content: ''; position: absolute; inset: 0; border-radius: inherit; z-index: -1; pointer-events: none; background: """ + NOISE + """; opacity: .045; mix-blend-mode: screen; }
  .s .door h2 { margin: 14px 0 10px; font: 300 38px/1.12 var(--sans); letter-spacing: -.015em; color: var(--ink); text-shadow: 0 2px 24px rgba(157,184,232,.25); }
  .s .door h2 b { font-weight: 600; }
  .s .door .fld .box { border-radius: 10px; padding: 0 16px; background: rgba(6,8,14,.38); box-shadow: inset 0 1px 3px rgba(0,0,0,.65), inset 0 -1px 0 rgba(255,255,255,.04), 0 0 0 1px var(--hair); }
  .s .door .fld.live .box { box-shadow: inset 0 1px 3px rgba(0,0,0,.65), inset 0 -1px 0 rgba(255,255,255,.04), 0 0 0 1px var(--accent), 0 0 22px -4px rgba(157,184,232,.55); }
  .s .door .fld.set .box { background: none; box-shadow: none; padding: 0; } .s .door .fld.set .box .key { font-size: 16px; letter-spacing: .05em; }
  .s .door .fld.off .box { box-shadow: 0 0 0 1px transparent; outline: 1px dashed var(--ink-3); outline-offset: -1px; background: rgba(6,8,14,.2); }
  .s .door .go { font: 600 14px var(--sans); color: var(--void); border-radius: 999px; padding: 12px 26px; background: linear-gradient(180deg, #bcd0f3, #93afe3);
    box-shadow: inset 0 1px 0 rgba(255,255,255,.55), inset 0 -1px 0 rgba(0,0,0,.15), 0 10px 28px -8px rgba(157,184,232,.75); }
  .s .door .go.off { background: rgba(6,8,14,.3); color: var(--ink-3); box-shadow: none; outline: 1px dashed var(--ink-3); }
  .s .door .alt { font: 600 12px var(--sans); color: var(--accent); border-radius: 999px; padding: 8px 16px; background: rgba(157,184,232,.07); box-shadow: inset 0 1px 0 rgba(255,255,255,.1), 0 0 0 1px var(--hair-2); }
  .s .door .alt.quiet { background: none; box-shadow: none; }
  .s .door .codes div { border-top: 1px solid rgba(255,255,255,.1); box-shadow: 0 -1px 0 rgba(0,0,0,.5); }
  .s .door .log { background: rgba(6,8,14,.3); border-radius: 0 8px 8px 0; }
  /* refused: the glass frosts, the outline goes to ink, a line is etched on the pane */
  .s .door.refused { backdrop-filter: blur(30px); box-shadow: inset 0 1px 0 rgba(255,255,255,.2), inset 0 -1px 0 rgba(0,0,0,.65), 0 50px 90px -30px rgba(0,0,0,.9), 0 0 0 1px var(--ink); }
  .s .door.refused::after { opacity: .14; } .s .door.refused::before { background: linear-gradient(112deg, rgba(255,255,255,.14) 0%, rgba(255,255,255,.03) 40%, rgba(255,255,255,.06)); }
  .s .door .said { margin-top: 20px; font: 600 14px var(--sans); color: var(--ink); padding: 12px 16px; border-left: 2px solid var(--ink); background: rgba(233,238,251,.045); border-radius: 0 8px 8px 0; text-shadow: 0 1px 0 rgba(0,0,0,.6); }
  .s .door .said span { color: var(--ink-2); font-weight: 400; }
  /* too many tries: a shutter is down behind the glass */
  .s .door.locked { background: linear-gradient(155deg, rgba(6,8,14,.55), rgba(6,8,14,.35)), repeating-linear-gradient(180deg, rgba(255,255,255,.035) 0 1px, transparent 1px 11px); backdrop-filter: blur(6px);
    box-shadow: inset 0 1px 0 rgba(255,255,255,.08), 0 50px 90px -30px rgba(0,0,0,.9); outline: 1px dashed var(--ink-3); outline-offset: -1px; }
  .s .door.locked::before { background: none; }
  .s .hall.timeout { justify-content: flex-end; padding-right: 60px; top: 190px; } .s .hall.timeout .door { width: 640px; } .s .hall.timeout .pane { backdrop-filter: blur(14px); }
  @media (prefers-reduced-motion: no-preference) {
    .s .door { animation: s-arrive .7s cubic-bezier(.2,.7,.2,1) both; }
    @keyframes s-arrive { from { opacity: 0; transform: translateZ(-420px) rotateY(-22deg); } }
    .s .door.refused { animation: s-arrive .7s both, s-shake .5s .7s ease-in-out; }
    @keyframes s-shake { 20%, 60% { transform: translateX(-5px); } 40%, 80% { transform: translateX(5px); } }
    .s .pane.cage { animation: s-breathe 4s ease-in-out infinite; }
    @keyframes s-breathe { 50% { box-shadow: inset 0 1px 0 rgba(255,255,255,.2), 0 0 0 1px rgba(157,184,232,.7), 0 0 90px -6px rgba(157,184,232,.7), 0 30px 60px -20px rgba(0,0,0,.7); } }
  }
"""


class S(Direction):
    letter, name = 's', 'smoked glass'
    refusal_words = 'frosts and its edge goes to ink'
    locked_words = 'has its shutter down behind the glass'

    def door(self, step, h2, sub, inner, a, cls=''):
        return f'<div class="door {cls}"><div class="step">{step}</div><h2>{h2}</h2><div class="sub">{sub}</div>{inner}{a}</div>'

    def hall(self, passed, d, ahead, kind):
        p = ''.join(f'<div class="pane done" aria-label="passed: {html.escape(t)}"><span>{t}</span></div>' for t in passed)
        a = ''.join(f'<div class="pane ahead" aria-label="ahead: {html.escape(t)}"><span>{t}</span></div>' for t in ahead)
        cage = '' if kind == 'timeout' else '<div class="pane cage" aria-label="ahead: the cage"><span>the cage</span></div>'
        extra = '' if kind == 'timeout' else '<div class="floor" aria-hidden="true"></div><div class="beam" aria-hidden="true"></div>'
        return f'{extra}<div class="hall {kind}" aria-label="the doors">{p}{d}{a}{cage}</div>'


# ================================================================ T · slate and ink
T_CSS = CONTENT + """
  .t { background: radial-gradient(1100px 820px at 18% -10%, rgba(233,238,251,.095), transparent 60%), radial-gradient(800px 400px at 70% 120%, rgba(80,115,205,.05), transparent 60%), var(--void); }
  .t .desk { position: absolute; inset: 0; background: """ + NOISE + """; opacity: .035; pointer-events: none; }
  .t .hall { position: absolute; left: 0; right: 0; top: 200px; height: 600px; }
  .t .card { position: absolute; border-radius: 4px; background: linear-gradient(160deg, rgba(255,255,255,.055), transparent 42%), linear-gradient(168deg, #161c2e, #0f1422 55%, #0c1019); isolation: isolate;
    box-shadow: inset 0 1px 0 rgba(255,255,255,.1), inset 0 0 0 1px rgba(255,255,255,.035), 0 1px 0 rgba(0,0,0,.7), 0 26px 50px -18px rgba(0,0,0,.95), 0 70px 100px -40px rgba(0,0,0,.85); }
  .t .card::before { content: ''; position: absolute; inset: 0; border-radius: inherit; background: """ + NOISE + """; opacity: .16; mix-blend-mode: soft-light; pointer-events: none; z-index: -1; }
  .t .card::after { content: ''; position: absolute; inset: 14px; border-radius: 2px; border: 1px solid rgba(233,238,251,.075); pointer-events: none; }
  .t .door { left: 300px; top: 0; width: 760px; min-height: 450px; padding: 54px 62px 46px; display: flex; flex-direction: column; z-index: 3; }
  .t .door.wide { width: 920px; left: 300px; } .t .door.tall { min-height: 560px; }
  .t .door .step { font: 600 10px var(--mono); letter-spacing: .2em; color: var(--ink-3); }
  .t .door h2 { margin: 16px 0 12px; font: 400 40px/1.12 var(--serif); letter-spacing: -.005em; color: var(--ink); text-shadow: 0 1px 0 rgba(255,255,255,.07), 0 -1px 0 rgba(0,0,0,.75); }
  .t .door h2 b { font-weight: 700; }
  .t .door .sub { font: 15.5px/1.55 var(--serif); color: var(--ink-2); max-width: 58ch; }
  .t .door .fld label { font: italic 13.5px var(--serif); letter-spacing: 0; text-transform: none; color: var(--ink-3); margin-bottom: 2px; }
  .t .door .fld .box { height: 44px; border-bottom: 1px solid var(--ink-3); font: 20px var(--serif); box-shadow: 0 1px 0 rgba(0,0,0,.6); }
  .t .door .fld.live .box { border-bottom: 1.5px solid var(--accent); box-shadow: 0 1px 0 rgba(0,0,0,.6), 0 2px 0 rgba(157,184,232,.18); }
  .t .door .fld.set .box { border-bottom-color: transparent; box-shadow: none; } .t .door .fld.off .box { border-bottom-style: dashed; }
  .t .door .fld .note { font: italic 12px var(--serif); }
  .t .door .go { font: 600 14px var(--sans); color: var(--void); background: var(--accent); padding: 12px 26px; border-radius: 3px;
    box-shadow: inset 0 1px 0 rgba(255,255,255,.4), inset 0 -1px 0 rgba(0,0,0,.2), 0 1px 0 rgba(0,0,0,.7), 0 10px 22px -8px rgba(157,184,232,.55); }
  .t .door .go.off { background: none; color: var(--ink-3); box-shadow: none; border: 1px dashed var(--ink-3); }
  .t .door .alt { font: italic 15px var(--serif); color: var(--accent); padding: 4px 2px; border-bottom: 1px solid rgba(157,184,232,.35); }
  .t .door .alt.quiet { color: var(--ink-3); border-bottom-color: var(--hair); }
  .t .door .acts .meta { font: italic 12.5px var(--serif); }
  .t .door .codes div { border-top: 1px solid var(--ink-3); } .t .door .codes div small { font: italic 11px var(--serif); letter-spacing: 0; }
  .t .door .log { border-left-color: var(--ink-3); }
  .t .door .wait b { font-family: var(--serif); font-weight: 400; }
  /* the passed doors: cards turned face down on the pile to the left, each stamped */
  .t .flip { width: 150px; height: 450px; left: 110px; top: 10px; background: linear-gradient(170deg, #0e1222, #0a0d17);
    box-shadow: inset 0 1px 0 rgba(255,255,255,.06), 0 1px 0 rgba(0,0,0,.8), 0 24px 40px -18px rgba(0,0,0,.95); transform-origin: 50% 96%; }
  .t .flip::after { border-color: rgba(233,238,251,.05); }
  .t .flip span { position: absolute; left: 16px; top: 74px; writing-mode: sideways-lr; font: italic 15px var(--serif); color: var(--ok); letter-spacing: .02em; white-space: nowrap; }
  .t .flip i { position: absolute; top: 24px; left: 14px; width: 30px; height: 30px; line-height: 26px; border: 2px solid var(--ok); border-radius: 50%; font: 700 14px/26px var(--mono); text-align: center; color: var(--ok); font-style: normal; transform: rotate(-12deg); -webkit-mask: """ + GRIT + """; mask: """ + GRIT + """; }
  /* the doors ahead: cards in the same file, behind this one, each with its tab */
  .t .next { left: 300px; top: 0; width: 760px; height: 460px; background: linear-gradient(168deg, #10152a, #0c1019); }
  .t .next::after { border-color: rgba(233,238,251,.04); }
  .t .tab { position: absolute; top: -30px; height: 31px; padding: 0 18px; line-height: 30px; font: 600 10px/30px var(--mono); letter-spacing: .18em; text-transform: uppercase; color: var(--ink-3); white-space: nowrap;
    border-radius: 5px 5px 0 0; background: linear-gradient(180deg, #121830, #0d1222); box-shadow: inset 0 1px 0 rgba(255,255,255,.08), inset 1px 0 0 rgba(255,255,255,.03), inset -1px 0 0 rgba(0,0,0,.4); }
  .t .door > .tab { color: var(--ink); background: linear-gradient(180deg, #1a2238, #151b2c); box-shadow: inset 0 1px 0 rgba(255,255,255,.12), 0 -8px 20px -10px rgba(0,0,0,.6); }
  .t .tab.cage { color: var(--ink-2); padding-left: 30px; }
  .t .tab.cage::before { content: ''; position: absolute; left: 12px; top: 11px; width: 9px; height: 9px; border-radius: 50%; background: radial-gradient(circle, #fff, var(--accent) 45%, transparent 72%); box-shadow: 0 0 14px 2px rgba(157,184,232,.6); }
  /* refused: a rubber stamp in ink */
  .t .door .said { align-self: flex-start; margin-top: 22px; margin-left: 4px; padding: 11px 22px 10px; border: 2.5px solid var(--ink); border-radius: 5px; font: 700 15px var(--mono); letter-spacing: .2em; text-transform: uppercase; color: var(--ink);
    transform: rotate(-4deg); position: relative; -webkit-mask: """ + GRIT + """; mask: """ + GRIT + """; }
  .t .door .said::before { content: ''; position: absolute; inset: 3px; border: 1px solid var(--ink); border-radius: inherit; }
  .t .door .said span { display: block; font: 600 9.5px var(--mono); letter-spacing: .14em; margin-top: 3px; color: var(--ink); }
  .t .door.refused { box-shadow: inset 0 1px 0 rgba(255,255,255,.1), inset 0 0 0 1px var(--ink), 0 1px 0 rgba(0,0,0,.7), 0 26px 50px -18px rgba(0,0,0,.95), 0 70px 100px -40px rgba(0,0,0,.85); }
  /* too many tries: a paper band around the card */
  .t .door.locked { background: linear-gradient(168deg, #0d1120, #0a0d17); } .t .door.locked::after { border-style: dashed; border-color: var(--ink-3); }
  .t .door.locked .wait { margin: 22px -62px 0; padding: 14px 62px; background: rgba(233,238,251,.05); border-top: 1px dashed var(--ink-3); border-bottom: 1px dashed var(--ink-3); box-shadow: 0 6px 14px -8px rgba(0,0,0,.8); }
  .t .hall.timeout { top: 196px; } .t .hall.timeout .door { left: 740px; width: 620px; } .t .hall.timeout .flip { left: 560px; }
  @media (prefers-reduced-motion: no-preference) {
    .t .door { animation: t-draw .6s cubic-bezier(.2,.7,.2,1) both; }
    @keyframes t-draw { from { opacity: 0; transform: translate(26px, 10px); } }
    .t .door .said { animation: t-stamp .35s .6s cubic-bezier(.3,1.6,.5,1) both; }
    @keyframes t-stamp { from { opacity: 0; transform: rotate(-4deg) scale(1.7); } }
    .t .tab.cage::before { animation: t-glow 4s ease-in-out infinite; } @keyframes t-glow { 50% { box-shadow: 0 0 22px 4px rgba(157,184,232,.75); } }
  }
"""


class T(Direction):
    letter, name = 't', 'slate and ink'
    refusal_words = 'is stamped, and its printed rule goes to ink'
    locked_words = 'is bound with a paper band'
    qr = 196

    def door(self, step, h2, sub, inner, a, cls=''):
        self._cls = cls
        return (step, h2, sub, inner, a, cls)

    def said(self, t, note):
        return f'<div class="said" role="status">{t}<span>{note}</span></div>'

    def hall(self, passed, d, ahead, kind):
        step, h2, sub, inner, a, cls = d
        rots = {1: [-4], 2: [-12, -4], 3: [-20, -12, -4]}[len(passed)] if passed else []
        p = ''.join(f'<div class="card flip" style="transform:rotate({r}deg);left:{(170 if kind != "timeout" else 600) + i*4}px" aria-label="passed: {html.escape(t)}"><i>✓</i><span>{t}</span></div>'
                    for i, (t, r) in enumerate(zip(passed, rots)))
        tabs_all = ahead + ([] if kind == 'timeout' else ['the cage'])
        width = 920 if cls == 'wide' else (620 if kind == 'timeout' else 760)
        # tabs right-aligned along the top edge, 170 px apart, the cage last
        n = len(tabs_all)
        nexts = ''
        for i, t in enumerate(tabs_all):
            right = (n - 1 - i) * 172 + 16
            is_cage = t == 'the cage'
            nexts += (f'<div class="card next" style="top:0;left:{300 + (i+1)*8}px;width:{width}px;height:{456 + (i+1)*7}px;z-index:{2-i}" aria-label="ahead: {html.escape(t)}">'
                      f'<div class="tab{" cage" if is_cage else ""}" style="right:{right}px">{t}</div></div>')
        mine = {'signin': 'sign in', 'factor': 'a code', 'firstrun': 'setup code', 'enrol': 'an authenticator', 'codes': 'recovery codes', 'timeout': 'carry on', 'refused': 'sign in', 'locked': 'sign in'}[kind]
        door = (f'<div class="card door {cls}"><div class="tab" style="left:16px">{mine}</div><div class="step">{step}</div><h2>{h2}</h2><div class="sub">{sub}</div>{inner}{a}</div>')
        desk = '' if kind == 'timeout' else '<div class="desk" aria-hidden="true"></div>'
        return f'{desk}<div class="hall {kind}" aria-label="the doors">{p}{nexts}{door}</div>'


# ================================================================ U · wire gates
U_CSS = CONTENT + """
  .u { background: radial-gradient(800px 500px at 86% 60%, rgba(157,184,232,.08), transparent 60%), var(--void); }
  .u .floor { position: absolute; left: 0; right: 0; bottom: 0; height: 240px; pointer-events: none; overflow: hidden; }
  .u .floor::before { content: ''; position: absolute; left: -200px; right: -200px; top: 0; height: 240px; transform-origin: top; transform: perspective(500px) rotateX(58deg);
    background: repeating-linear-gradient(90deg, rgba(157,184,232,.09) 0 2px, transparent 2px 19px); -webkit-mask: linear-gradient(to bottom, rgba(0,0,0,.9), transparent 85%); mask: linear-gradient(to bottom, rgba(0,0,0,.9), transparent 85%); }
  .u .floor::after { content: ''; position: absolute; inset: 0; background: linear-gradient(to top, rgba(157,184,232,.05), transparent 60%); }
  .u .hall { position: absolute; left: 0; right: 0; top: 100px; height: 680px; display: flex; justify-content: center; align-items: flex-end; gap: 26px; padding-bottom: 52px; }
  .u .arch { position: relative; border-radius: 50% 50% 0 0 / 38% 38% 0 0; border: 1.5px solid var(--ink-2); isolation: isolate;
    box-shadow: inset 0 0 0 1px rgba(233,238,251,.07), inset 0 0 0 6px var(--void), inset 0 0 0 7px rgba(151,164,196,.38), 0 40px 70px -30px rgba(0,0,0,.9); }
  .u .arch .wires { position: absolute; inset: 8px; border-radius: inherit; z-index: -1; pointer-events: none; overflow: hidden;
    background: repeating-linear-gradient(90deg, rgba(151,164,196,.6) 0 1px, rgba(255,255,255,.07) 1px 2px, transparent 2px 17px); }
  .u .arch .fan { position: absolute; left: 8px; right: 8px; top: 8px; height: 30%; border-radius: 50% 50% 0 0 / 100% 100% 0 0; z-index: -1; pointer-events: none;
    background: repeating-conic-gradient(from 270deg at 50% 100%, rgba(151,164,196,.55) 0deg .5deg, transparent .5deg 9deg); border-bottom: 1px solid rgba(151,164,196,.5); }
  .u .arch > span { writing-mode: sideways-lr; font: 600 11px var(--mono); letter-spacing: .22em; text-transform: uppercase; color: var(--ink-3); white-space: nowrap; position: absolute; left: 50%; top: 62%; transform: translate(-50%, -50%); padding: 12px 5px; background: var(--void); border-radius: 3px; }
  .u .arch.done { width: 72px; height: 520px; border-color: var(--ok); box-shadow: inset 0 0 0 1px rgba(55,179,100,.15), inset 0 0 0 6px var(--void), inset 0 0 0 7px rgba(55,179,100,.35), 0 40px 70px -30px rgba(0,0,0,.9), 0 0 40px -12px rgba(55,179,100,.35); }
  .u .arch.done .wires { background: repeating-linear-gradient(90deg, rgba(55,179,100,.45) 0 1px, transparent 1px 12px); -webkit-mask: linear-gradient(90deg, black 20%, transparent 40%, transparent 60%, black 80%); mask: linear-gradient(90deg, black 20%, transparent 40%, transparent 60%, black 80%); }
  .u .arch.done .fan { background: repeating-conic-gradient(from 270deg at 50% 100%, rgba(55,179,100,.5) 0deg 1deg, transparent 1deg 15deg); border-bottom-color: rgba(55,179,100,.5); }
  .u .arch.done > span { color: var(--ok); }
  .u .arch.done::before { content: '✓'; position: absolute; top: 33%; left: 0; right: 0; margin-top: 0; text-align: center; font: 700 12px var(--mono); color: var(--ok); z-index: 2; }
  .u .arch.ahead { border: 1px dashed var(--hair-2); box-shadow: inset 0 0 0 6px var(--void), inset 0 0 0 7px rgba(151,164,196,.12), 0 40px 70px -30px rgba(0,0,0,.9); }
  .u .arch.ahead .wires { background: repeating-linear-gradient(90deg, rgba(151,164,196,.22) 0 1px, transparent 1px 13px); }
  .u .arch.ahead .fan { background: repeating-conic-gradient(from 270deg at 50% 100%, rgba(151,164,196,.2) 0deg 1deg, transparent 1deg 15deg); border-bottom-color: rgba(151,164,196,.18); }
  .u .arch.a1 { width: 124px; height: 420px; } .u .arch.a2 { width: 100px; height: 340px; }
  .u .arch.cage { width: 88px; height: 290px; border: 1px solid var(--accent); box-shadow: inset 0 0 0 5px var(--void), inset 0 0 0 6px rgba(157,184,232,.5), 0 0 70px -8px rgba(157,184,232,.6), 0 40px 70px -30px rgba(0,0,0,.9);
    background: radial-gradient(ellipse at 50% 75%, rgba(157,184,232,.35), rgba(157,184,232,.05) 70%); }
  .u .arch.cage .wires { background: repeating-linear-gradient(90deg, rgba(157,184,232,.9) 0 1px, transparent 1px 6px); inset: 7px; }
  .u .arch.cage .fan { background: repeating-conic-gradient(from 270deg at 50% 100%, rgba(157,184,232,.9) 0deg .8deg, transparent .8deg 7deg); left: 7px; right: 7px; top: 7px; border-bottom-color: rgba(157,184,232,.8); }
  .u .arch.cage > span { color: var(--ink); font-size: 10px; }
  .u .door { width: 760px; min-height: 540px; padding: 0 70px 44px; display: flex; flex-direction: column; justify-content: flex-start; }
  .u .door.wide { width: 920px; min-height: 580px; } .u .door.tall { min-height: 620px; }
  .u .door .wires { -webkit-mask: radial-gradient(ellipse 70% 80% at 50% 62%, transparent 60%, black 100%); mask: radial-gradient(ellipse 70% 80% at 50% 62%, transparent 60%, black 100%); }
  .u .door .fan { height: 36%; -webkit-mask: radial-gradient(ellipse at 50% 100%, transparent 48%, black 82%); mask: radial-gradient(ellipse at 50% 100%, transparent 48%, black 82%); }
  .u .door .step { margin-top: 92px; text-align: center; } .u .door.wide .step, .u .door.tall .step { margin-top: 84px; }
  .u .door h2 { margin: 14px auto 10px; font: 700 38px/1.1 var(--sans); letter-spacing: -.02em; color: var(--ink); text-align: center; max-width: 24ch; }
  .u .door h2 b { color: var(--accent); }
  .u .door .sub { margin: 0 auto; text-align: center; max-width: 56ch; }
  .u .door .fields { margin-top: 22px; }
  .u .door .fld .box { position: relative; border-bottom: 1.5px solid var(--ink-3); padding: 0 12px; height: 44px; }
  .u .door .fld .box::before, .u .door .fld .box::after { content: ''; position: absolute; width: 8px; height: 8px; border-radius: 50%; border: 1.5px solid var(--ink-3); background: var(--void); bottom: -4.5px; }
  .u .door .fld .box::before { left: -4px; } .u .door .fld .box::after { right: -4px; }
  .u .door .fld.live .box { border-bottom-color: var(--accent); box-shadow: 0 8px 18px -10px rgba(157,184,232,.7); }
  .u .door .fld.live .box::before, .u .door .fld.live .box::after { border-color: var(--accent); box-shadow: 0 0 8px rgba(157,184,232,.6); }
  .u .door .fld.set .box { border-bottom-color: transparent; box-shadow: none; } .u .door .fld.set .box::before, .u .door .fld.set .box::after { display: none; }
  .u .door .fld.off .box { border-bottom-style: dashed; } .u .door .fld.off .box::before, .u .door .fld.off .box::after { border-style: dashed; }
  .u .door .acts { justify-content: center; flex-wrap: wrap; row-gap: 12px; } .u .door .acts .sp { display: none; } .u .door .acts button { white-space: nowrap; flex: none; } .u .door .acts .meta { width: 100%; text-align: center; }
  .u .door .go { font: 700 14px var(--sans); color: var(--void); border-radius: 999px; padding: 12px 28px; background: var(--accent); box-shadow: 0 0 0 4px var(--void), 0 0 0 5px rgba(157,184,232,.5), 0 12px 28px -10px rgba(157,184,232,.7); }
  .u .door .go.off { background: none; color: var(--ink-3); box-shadow: 0 0 0 4px var(--void), 0 0 0 5px transparent; border: 1px dashed var(--ink-3); }
  .u .door .alt { font: 600 12px var(--sans); color: var(--accent); border: 1px solid var(--hair-2); border-radius: 999px; padding: 8px 16px; }
  .u .door .codes { margin-top: 20px; } .u .door .codes div { border-top: 1.5px solid var(--ink-3); position: relative; }
  .u .door .codes div::before { content: ''; position: absolute; left: -3px; top: -4px; width: 6px; height: 6px; border-radius: 50%; border: 1.5px solid var(--ink-3); background: var(--void); }
  .u .door .two { margin-top: 20px; align-items: center; } .u .door .two .fields { margin-top: 0; }
  .u .door .log { margin: 14px auto 0; max-width: 560px; }
  .u .door .wait { justify-content: center; } .u .door .wait b { font-weight: 500; }
  /* refused: the wires go to ink and a tag hangs from one */
  .u .door.refused { border-color: var(--ink); box-shadow: inset 0 0 0 1px rgba(233,238,251,.1), inset 0 0 0 6px var(--void), inset 0 0 0 7px rgba(233,238,251,.5), 0 40px 70px -30px rgba(0,0,0,.9); }
  .u .door.refused .wires { background: repeating-linear-gradient(90deg, rgba(233,238,251,.75) 0 1px, rgba(255,255,255,.1) 1px 2px, transparent 2px 17px); }
  .u .door.refused .fan { background: repeating-conic-gradient(from 270deg at 50% 100%, rgba(233,238,251,.7) 0deg .5deg, transparent .5deg 9deg); border-bottom-color: rgba(233,238,251,.6); }
  .u .door .said { align-self: center; margin-top: 26px; padding: 10px 16px 10px 16px; border: 1px solid var(--ink); border-radius: 3px; font: 600 13.5px var(--sans); color: var(--ink); position: relative; transform: rotate(-1.5deg); background: var(--void); box-shadow: 0 10px 20px -10px rgba(0,0,0,.9); }
  .u .door .said::before { content: ''; position: absolute; left: 50%; top: -12px; width: 9px; height: 9px; margin-left: -5.5px; border: 1.5px solid var(--ink); border-radius: 50%; background: var(--void); }
  .u .door .said::after { content: ''; position: absolute; left: 50%; top: -22px; height: 10px; border-left: 1px solid var(--ink); }
  .u .door .said span { color: var(--ink-2); font-weight: 400; }
  /* too many tries: the gate is meshed shut */
  .u .door.locked { border: 1.5px dashed var(--ink-3); box-shadow: inset 0 0 0 6px var(--void), inset 0 0 0 7px rgba(85,98,138,.3), 0 40px 70px -30px rgba(0,0,0,.9); }
  .u .door.locked .wires { background: repeating-linear-gradient(90deg, rgba(85,98,138,.5) 0 1px, transparent 1px 17px), repeating-linear-gradient(0deg, rgba(85,98,138,.35) 0 1px, transparent 1px 17px);
    -webkit-mask: radial-gradient(ellipse 60% 70% at 50% 60%, transparent 46%, black 100%); mask: radial-gradient(ellipse 60% 70% at 50% 60%, transparent 46%, black 100%); }
  .u .door.locked .fan { background: repeating-conic-gradient(from 270deg at 50% 100%, rgba(85,98,138,.4) 0deg .5deg, transparent .5deg 9deg); border-bottom-color: rgba(85,98,138,.4); }
  .u .hall.timeout { justify-content: flex-end; padding-right: 60px; top: 150px; } .u .hall.timeout .door { width: 640px; min-height: 540px; background: rgba(6,8,14,.9); } .u .hall.timeout .arch.done { background: var(--void); }
  @media (prefers-reduced-motion: no-preference) {
    .u .door { animation: u-forward .7s cubic-bezier(.2,.7,.2,1) both; }
    @keyframes u-forward { from { opacity: 0; transform: translateX(120px) scale(.6); } }
    .u .door.refused { animation: u-forward .7s both, u-rattle .5s .7s ease-in-out; }
    @keyframes u-rattle { 20%, 60% { transform: translateX(-4px); } 40%, 80% { transform: translateX(4px); } }
    .u .arch.cage { animation: u-breathe 4s ease-in-out infinite; }
    @keyframes u-breathe { 50% { box-shadow: inset 0 0 0 5px var(--void), inset 0 0 0 6px rgba(157,184,232,.7), 0 0 90px -4px rgba(157,184,232,.75), 0 40px 70px -30px rgba(0,0,0,.9); } }
  }
"""


class U(Direction):
    letter, name = 'u', 'wire gates'
    refusal_words = '\'s wires go to ink and a tag hangs from one'
    locked_words = 'is meshed shut and drawn dashed'
    qr = 184

    def door(self, step, h2, sub, inner, a, cls=''):
        return (f'<div class="arch door {cls}"><div class="wires" aria-hidden="true"></div><div class="fan" aria-hidden="true"></div>'
                f'<div class="step">{step}</div><h2>{h2}</h2><div class="sub">{sub}</div>{inner}{a}</div>')

    def hall(self, passed, d, ahead, kind):
        arch = lambda t, cls: f'<div class="arch {cls}" aria-label="{html.escape(cls.split()[0])}: {html.escape(t)}"><div class="wires" aria-hidden="true"></div><div class="fan" aria-hidden="true"></div><span>{t}</span></div>'
        p = ''.join(arch(t, 'done') for t in passed)
        a = ''.join(arch(t, f'ahead a{i+1}') for i, t in enumerate(ahead))
        cage = '' if kind == 'timeout' else arch('the cage', 'cage')
        floor = '' if kind == 'timeout' else '<div class="floor" aria-hidden="true"></div>'
        return f'{floor}<div class="hall {kind}" aria-label="the doors">{p}{d}{a}{cage}</div>'


# ================================================================ motion showcases
# One page per direction: door one, door two, the cage; a 12 s loop. Without motion
# the page is the still after door one has been passed: door two faces you.
MOTION_BASE = """
  .stage { position: relative; width: 1440px; height: 900px; margin: 0 auto; overflow: hidden; background: var(--void); }
  .stage .cap { position: absolute; left: 50%; transform: translateX(-50%); bottom: 16px; white-space: nowrap; padding: 6px 14px; border-radius: 999px; background: var(--void); text-align: center; font: 12.5px var(--sans); color: var(--ink-2); z-index: 8; }
  .stage .into { position: absolute; inset: 0; display: flex; align-items: center; justify-content: center; flex-direction: column; gap: 12px; opacity: 0; z-index: 6; pointer-events: none; }
  .stage .into b { font: 300 56px var(--sans); letter-spacing: -.02em; color: var(--ink); } .stage .into b strong { font-weight: 600; }
  .stage .into i { font: 600 10px var(--mono); letter-spacing: .24em; text-transform: uppercase; color: var(--ink-2); font-style: normal; }
  .stage .still { position: absolute; top: 18px; left: 50%; transform: translateX(-50%); font: 10px var(--mono); letter-spacing: .14em; text-transform: uppercase; color: var(--ink-3); z-index: 5; }
  @media (prefers-reduced-motion: no-preference) { .stage .still { display: none; } }
"""


def motion_page(D, css, body, cap):
    return page(f'Birdcage · round 9 · {D.letter.upper()} · {D.name} · motion',
                css + MOTION_BASE,
                f'<div class="stage {D.letter}" role="region" aria-label="{D.letter.upper()}, {D.name}: the motion, door to door and into the cage">'
                f'<div class="still">still · reduced motion · door one passed, door two faces you</div>{chrome()}{body}'
                f'<div class="into" aria-hidden="true"><b>The cage is <strong>yours</strong>.</b><i>09:18:12 · ada · in</i></div>'
                f'<div class="cap">{cap}</div></div>')


def door_one(D):
    return D.door(f'the door · {DAY} · {NOW}', 'Say who you are.',
                  f'Birdcage is watching four canaries. Nothing they have seen is shown until you are through. You are <span class="ip">{IP}</span>.',
                  '<div class="fields">' + fld('who', 'ada', 'live') + fld('password', '<span>••••••••••••</span>', 'live') + '</div>',
                  acts('sign in ▸', [('use a passkey', ''), ('sign in with SSO', 'quiet')], 'then a code, then the cage'))


def door_two(D):
    return D.door(f'the door · {DAY} · 09:18:09 · second of three', '<b>ada</b>, one more thing.',
                  'A code from your authenticator app: six digits, a new one every thirty seconds. If the phone is gone, a recovery code opens this door once.',
                  '<div class="fields one">' + fld('code', '<span class="digits">417 926</span>', 'live', 'accepted') + '</div>',
                  acts('continue ▸', [('use a recovery code instead', 'quiet')], 'ada last signed in thu 13 nov 09:41'))


S_MOTION = """
  .s .hall { perspective: 1500px; }
  .s .hall > * { position: absolute; }
  .s .d1 { left: 50%; margin-left: -380px; top: 40px; transform-origin: left center; opacity: 0; }
  .s .p1 { left: 50%; margin-left: -520px; top: 40px; }
  .s .d2 { left: 50%; margin-left: -380px; top: 40px; transform-origin: left center; }
  .s .p2 { left: 50%; margin-left: 400px; top: 40px; }
  .s .pane.cg { left: 50%; margin-left: 540px; top: 40px; transform-origin: center; }
  @media (prefers-reduced-motion: no-preference) {
    .s .d1 { animation: m-d1 12s cubic-bezier(.4,0,.2,1) infinite; }
    @keyframes m-d1 { 0% { opacity: 0; transform: translateZ(-420px) rotateY(-22deg); } 6%, 22% { opacity: 1; transform: none; } 30%, 100% { opacity: 0; transform: rotateY(-82deg); } }
    .s .p1 { animation: m-p1 12s infinite; } @keyframes m-p1 { 0%, 28% { opacity: 0; } 34%, 70% { opacity: 1; } 78%, 100% { opacity: 0; } }
    .s .p2 { animation: m-p2 12s infinite; } @keyframes m-p2 { 0%, 26% { opacity: 1; } 32%, 100% { opacity: 0; } }
    .s .d2 { animation: m-d2 12s cubic-bezier(.4,0,.2,1) infinite; }
    @keyframes m-d2 { 0%, 26% { opacity: 0; transform: translateX(640px) translateZ(-700px) rotateY(-40deg); } 36%, 56% { opacity: 1; transform: none; } 64%, 100% { opacity: 0; transform: rotateY(-82deg); } }
    .s .pane.cg { animation: m-cg 12s cubic-bezier(.4,0,.2,1) infinite; }
    @keyframes m-cg { 0%, 62% { transform: rotateY(-32deg); opacity: 1; } 76% { transform: translateX(-540px) scale(14); opacity: 1; } 82% { transform: translateX(-540px) scale(14); opacity: .3; } 90% { transform: translateX(-540px) scale(14); opacity: .25; } 94%, 100% { transform: translateX(-540px) scale(14); opacity: 0; } }
    .s .cg span { animation: m-cgs 12s infinite; } @keyframes m-cgs { 0%, 64% { opacity: 1; } 68%, 100% { opacity: 0; } }
    .s .into { animation: m-into 12s infinite; } @keyframes m-into { 0%, 74% { opacity: 0; } 80%, 90% { opacity: 1; } 96%, 100% { opacity: 0; } }
  }
"""

T_MOTION = """
  .t .hall > * { position: absolute; }
  .t .d1 { left: 300px; top: 20px; transform-origin: left center; opacity: 0; z-index: 4; }
  .t .d2 { left: 300px; top: 20px; z-index: 3; transform-origin: left center; }
  .t .f1 { left: 150px; top: 30px; transform: rotate(-4deg); }
  .t .n2 { left: 308px; top: 20px; width: 760px; height: 463px; z-index: 2; }
  .t .nc { left: 316px; top: 20px; width: 760px; height: 470px; z-index: 1; }
  .t .nc .tab::before { transform-origin: center; }
  .t .light { position: absolute; left: 50%; top: 50%; width: 10px; height: 10px; margin: -5px 0 0 -5px; border-radius: 50%; background: radial-gradient(circle, rgba(233,238,251,.9), rgba(157,184,232,.35) 30%, rgba(157,184,232,.08) 55%, transparent 70%); opacity: 0; z-index: 5; }
  @media (prefers-reduced-motion: no-preference) {
    .t .d1 { animation: m-d1 12s cubic-bezier(.4,0,.2,1) infinite; }
    @keyframes m-d1 { 0% { opacity: 0; transform: translate(26px,10px); } 5%, 22% { opacity: 1; transform: none; } 25% { transform: translateY(-14px) rotateY(0); } 31%, 100% { opacity: 0; transform: translate(-200px, 10px) rotateY(-180deg); } }
    .t .f1 { animation: m-f1 12s infinite; } @keyframes m-f1 { 0%, 29% { opacity: 0; } 32%, 70% { opacity: 1; } 78%, 100% { opacity: 0; } }
    .t .n2 { animation: m-n2 12s infinite; } @keyframes m-n2 { 0%, 30% { opacity: 1; } 32%, 100% { opacity: 0; } }
    .t .d2 { animation: m-d2 12s cubic-bezier(.4,0,.2,1) infinite; }
    @keyframes m-d2 { 0%, 30% { opacity: 0; transform: translate(7px,7px); } 36%, 56% { opacity: 1; transform: none; } 59% { transform: translateY(-14px); } 65%, 100% { opacity: 0; transform: translate(-200px, 10px) rotateY(-180deg); } }
    .t .nc { animation: m-nc 12s cubic-bezier(.4,0,.2,1) infinite; } @keyframes m-nc { 0%, 64% { transform: none; } 70%, 100% { transform: translate(-14px,-14px); } }
    .t .light { animation: m-light 12s cubic-bezier(.4,0,.2,1) infinite; } @keyframes m-light { 0%, 68% { opacity: 0; transform: scale(1); } 72% { opacity: 1; transform: scale(8); } 84% { opacity: 1; transform: scale(150); } 94%, 100% { opacity: 0; transform: scale(150); } }
    .t .into { animation: m-into 12s infinite; } @keyframes m-into { 0%, 76% { opacity: 0; } 82%, 90% { opacity: 1; } 96%, 100% { opacity: 0; } }
  }
"""

U_MOTION = """
  .u .hall > * { position: absolute; bottom: 52px; }
  .u .d1 { left: 50%; margin-left: -380px; opacity: 0; transform-origin: center 70%; }
  .u .d2 { left: 50%; margin-left: -380px; transform-origin: center 70%; }
  .u .g1 { left: 50%; margin-left: -500px; }
  .u .g2 { left: 50%; margin-left: 406px; }
  .u .arch.cg { left: 50%; margin-left: 556px; transform-origin: center 70%; }
  .u .door .wl, .u .door .wr { position: absolute; top: 8px; bottom: 8px; width: 50%; z-index: -1; pointer-events: none; overflow: hidden;
    background: repeating-linear-gradient(90deg, rgba(151,164,196,.6) 0 1px, rgba(255,255,255,.07) 1px 2px, transparent 2px 17px); }
  .u .door .wl { left: 8px; border-radius: 100% 0 0 0 / 38% 0 0 0; -webkit-mask: radial-gradient(ellipse 128% 72% at 100% 60%, transparent 52%, black 100%); mask: radial-gradient(ellipse 128% 72% at 100% 60%, transparent 52%, black 100%); }
  .u .door .wr { right: 8px; border-radius: 0 100% 0 0 / 0 38% 0 0; -webkit-mask: radial-gradient(ellipse 128% 72% at 0% 60%, transparent 52%, black 100%); mask: radial-gradient(ellipse 128% 72% at 0% 60%, transparent 52%, black 100%); }
  .u .door > .wires { display: none; }
  @media (prefers-reduced-motion: no-preference) {
    .u .d1 { animation: m-d1 12s cubic-bezier(.4,0,.2,1) infinite; }
    @keyframes m-d1 { 0% { opacity: 0; transform: translateX(120px) scale(.6); } 6%, 22% { opacity: 1; transform: none; } 30%, 100% { opacity: 0; transform: scale(1.6); } }
    .u .d1 .wl { animation: m-wl 12s cubic-bezier(.4,0,.2,1) infinite; } .u .d1 .wr { animation: m-wr 12s cubic-bezier(.4,0,.2,1) infinite; }
    .u .d2 .wl { animation: m-wl2 12s cubic-bezier(.4,0,.2,1) infinite; } .u .d2 .wr { animation: m-wr2 12s cubic-bezier(.4,0,.2,1) infinite; }
    @keyframes m-wl { 0%, 20% { transform: none; } 27%, 100% { transform: translateX(-100%); } } @keyframes m-wr { 0%, 20% { transform: none; } 27%, 100% { transform: translateX(100%); } }
    @keyframes m-wl2 { 0%, 54% { transform: none; } 61%, 100% { transform: translateX(-100%); } } @keyframes m-wr2 { 0%, 54% { transform: none; } 61%, 100% { transform: translateX(100%); } }
    .u .g1 { animation: m-g1 12s infinite; } @keyframes m-g1 { 0%, 27% { opacity: 0; } 33%, 70% { opacity: 1; } 78%, 100% { opacity: 0; } }
    .u .g2 { animation: m-g2 12s infinite; } @keyframes m-g2 { 0%, 24% { opacity: 1; } 30%, 100% { opacity: 0; } }
    .u .d2 { animation: m-d2 12s cubic-bezier(.4,0,.2,1) infinite; }
    @keyframes m-d2 { 0%, 24% { opacity: 0; transform: translateX(760px) scale(.16); } 36%, 56% { opacity: 1; transform: none; } 64%, 100% { opacity: 0; transform: scale(1.6); } }
    .u .arch.cg { animation: m-cg 12s cubic-bezier(.4,0,.2,1) infinite; }
    @keyframes m-cg { 0%, 60% { transform: none; opacity: 1; } 76% { transform: translateX(-556px) translateY(60px) scale(9); opacity: 1; } 82% { transform: translateX(-556px) translateY(60px) scale(9); opacity: .3; } 90% { transform: translateX(-556px) translateY(60px) scale(9); opacity: .25; } 94%, 100% { transform: translateX(-556px) translateY(60px) scale(9); opacity: 0; } }
    .u .cg span { animation: m-cgs 12s infinite; } @keyframes m-cgs { 0%, 62% { opacity: 1; } 66%, 100% { opacity: 0; } }
    .u .into { animation: m-into 12s infinite; } @keyframes m-into { 0%, 76% { opacity: 0; } 82%, 90% { opacity: 1; } 96%, 100% { opacity: 0; } }
  }
"""


def build_motion(D):
    L = D.letter
    if L == 's':
        d1 = door_one(D).replace('class="door ', 'class="door d1 ', 1)
        d2 = door_two(D).replace('class="door ', 'class="door d2 ', 1)
        body = ('<div class="floor" aria-hidden="true"></div><div class="beam" aria-hidden="true"></div><div class="hall" aria-label="the doors">'
                '<div class="pane done p1" aria-label="passed: ada · password"><span>ada · password</span></div>'
                f'{d1}{d2}'
                '<div class="pane ahead p2" aria-label="ahead: a code"><span>a code</span></div>'
                '<div class="pane cage cg" aria-label="ahead: the cage"><span>the cage</span></div></div>')
        cap = 'S · smoked glass · the door you have passed swings away on its hinge; the next arrives out of the depth; the cage\'s light fills the pane, then the room'
        return motion_page(D, S_CSS + S_MOTION, body, cap)
    if L == 't':
        s1 = door_one(D)
        s2 = door_two(D)
        card = lambda parts, extra, tab: (f'<div class="card door {extra}"><div class="tab" style="left:16px">{tab}</div><div class="step">{parts[0]}</div><h2>{parts[1]}</h2>'
                                          f'<div class="sub">{parts[2]}</div>{parts[3]}{parts[4]}</div>')
        body = ('<div class="desk" aria-hidden="true"></div><div class="hall" aria-label="the doors">'
                '<div class="card flip f1" aria-label="passed: ada · password"><i>✓</i><span>ada · password</span></div>'
                '<div class="card next nc" aria-label="ahead: the cage"><div class="tab cage" style="right:16px">the cage</div></div>'
                '<div class="card next n2" aria-label="ahead: a code"><div class="tab" style="right:188px">a code</div></div>'
                + card(s1, 'd1', 'sign in') + card(s2, 'd2', 'a code') +
                '<div class="light" aria-hidden="true"></div></div>')
        cap = 'T · slate and ink · the card you have passed lifts and turns face down onto the pile; the next card comes forward from its tab; the last card\'s light opens and fills the desk'
        return motion_page(D, T_CSS + T_MOTION, body, cap)
    d1 = door_one(D).replace('class="arch door ', 'class="arch door d1 ', 1).replace('<div class="wires" aria-hidden="true"></div>', '<div class="wl" aria-hidden="true"></div><div class="wr" aria-hidden="true"></div>', 1)
    d2 = door_two(D).replace('class="arch door ', 'class="arch door d2 ', 1).replace('<div class="wires" aria-hidden="true"></div>', '<div class="wl" aria-hidden="true"></div><div class="wr" aria-hidden="true"></div>', 1)
    arch = lambda t, cls: f'<div class="arch {cls}" aria-label="{cls.split()[0]}: {t}"><div class="wires" aria-hidden="true"></div><div class="fan" aria-hidden="true"></div><span>{t}</span></div>'
    body = ('<div class="floor" aria-hidden="true"></div><div class="hall" aria-label="the doors">'
            + arch('ada · password', 'done g1') + d1 + d2 + arch('a code', 'ahead a1 g2') + arch('the cage', 'cage cg') + '</div>')
    cap = 'U · wire gates · the gate\'s wires part down the middle and you walk through it; the next arch comes up the corridor to meet you; the cage grows until its wires fill the room, and they part too'
    return motion_page(D, U_CSS + U_MOTION, body, cap)


def build_dir(D, css):
    return page(f'Birdcage · round 9 · {D.letter.upper()} · {D.name}', css, '\n\n'.join(scenes_for(D)))


if __name__ == '__main__':
    for D, css in [(S(), S_CSS), (T(), T_CSS), (U(), U_CSS)]:
        fn = dict((l, f) for l, _, f in DIRS)[D.letter]
        with open(fn, 'w') as f:
            f.write(build_dir(D, css))
        print(fn)
        mf = f'motion-{D.letter}.html'
        with open(mf, 'w') as f:
            f.write(build_motion(D))
        print(mf)
