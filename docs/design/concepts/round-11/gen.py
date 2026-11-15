#!/usr/bin/env python3
"""Round 11: smoked glass, no card (#8, slice B). Round 10's verdict was "played it safe":
every round so far was a dark page, a rounded card holding a form, and an idea around it.
This round keeps smoked glass and birdcage's identity and drops the card. Three directions,
each a different place to stand relative to the glass: Y you stand at the sheet and walk
through it; Z the glass is a closed door and the only light is the brink's, at its edge;
AA the glass is the floor you stand on and the form stands in the room, reflected.
Same copy, data and eight scenes as round 10; palette, type roots and chrome are round
6/7's, copied so the round stands alone. The light in Y and Z is a WebGL fragment shader
(refraction, falloff, bevels); AA's reflection is the DOM mirrored. Each has a CSS fallback.
Run here: python3 gen.py  ->  direction-{y,z,aa}-*.html, motion-{y,z,aa}.html"""
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
DIRS = [('y', 'through the glass', 'direction-y-through-the-glass.html'),
        ('z', 'ajar', 'direction-z-ajar.html'),
        ('aa', 'the floor', 'direction-aa-the-floor.html')]
# the step each scene is on, the steps passed and the steps ahead, for the rail
STEPS = {'signin': ([], 'Password', ['Authentication code']),
         'factor': (['Password'], 'Authentication code', []),
         'firstrun': ([], 'Administrator', ['Authenticator', 'Recovery codes']),
         'enrol': (['Administrator'], 'Authenticator', ['Recovery codes']),
         'codes': (['Administrator', 'Authenticator'], 'Recovery codes', []),
         'timeout': (['Signed in 07:31'], 'Password', []),
         'refused': ([], 'Password', ['Authentication code']),
         'locked': ([], 'Password', ['Authentication code'])}
WIDE = {'enrol', 'codes'}
TALL = {'firstrun'}
MOOD = {'refused': 1, 'locked': 2}   # 0 lit, 1 ink, 2 paused (dashed)


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


def qr_svg(size=176, cls='qr'):
    g = qr_modules()
    n = len(g)
    m = size / n
    rects = ''.join(f'<rect x="{c*m:.1f}" y="{r*m:.1f}" width="{m+.2:.1f}" height="{m+.2:.1f}"/>'
                    for r in range(n) for c in range(n) if g[r][c])
    return (f'<svg class="{cls}" width="{size}" height="{size}" viewBox="0 0 {size} {size}" role="img" '
            f'aria-label="QR code for the authenticator app (placeholder pattern)">{rects}</svg>')


# ---------------------------------------------------------------- the shell's geometry (round 6 M at 1440 wide)
X0, X1 = 190, 1368  # the band: lane labels end in the gutter at X0; the brink stands at X1
BANDY = 300        # the first of four lines, 12 px apart

# ---------------------------------------------------------------- shared css (round 6/7 roots, round 10's shell)
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
  input, button { font: inherit; color: inherit; }
  input { background: none; border: 0; outline: 0; padding: 0; margin: 0; }
  button { background: none; border: 0; padding: 0; margin: 0; cursor: pointer; }
  button:focus-visible, input:focus-visible { outline: 2px solid var(--accent); outline-offset: 3px; }
  .ip { font-family: var(--mono); }
  .caret { display: inline-block; width: 1.5px; height: 1em; background: var(--accent); vertical-align: -.15em; margin-left: 1px; }
  .sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); }
  canvas.gl { position: absolute; left: 0; top: 0; width: 1440px; height: 900px; display: block; }
  .nogl canvas.gl { display: none; }
  @media (prefers-reduced-motion: no-preference) {
    .caret { animation: blink 1.1s steps(2, start) infinite; }
    @keyframes blink { to { visibility: hidden; } }
  }

  /* the ratified shell, round 6 M, quiet: behind the timed-out door, dimmed, and the first view after the last step */
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
    or the first view after the last step."""
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


# ---------------------------------------------------------------- the light: one fragment shader per direction
GLSL_HEAD = """precision highp float;
uniform vec2 R; uniform float T; uniform float M; uniform float W; uniform float E1; uniform float E2; uniform float HZ;
float h(vec2 p){ return fract(sin(dot(p, vec2(127.1,311.7)))*43758.5453); }
float n(vec2 p){ vec2 i=floor(p), f=fract(p); f=f*f*(3.-2.*f);
  return mix(mix(h(i),h(i+vec2(1,0)),f.x), mix(h(i+vec2(0,1)),h(i+vec2(1,1)),f.x), f.y); }
float fbm(vec2 p){ float v=0., a=.5; for(int i=0;i<5;i++){ v+=a*n(p); p=p*2.03+vec2(17.,9.); a*=.5; } return v; }
vec3 ink(vec3 c){ float l=dot(c,vec3(.3,.5,.2)); return mix(c, vec3(l)*vec3(.93,.96,1.05), .85)*.55; }
"""

# Y: a thick sheet of rolled glass right in front of you. Behind it a lit room with no data in it;
# the sheets still ahead stand deeper in the room and their lit edges waver through the near sheet.
GLSL_Y = GLSL_HEAD + """
void main(){
  vec2 uv = gl_FragCoord.xy / R; vec2 px = vec2(uv.x*R.x, (1.-uv.y)*R.y);
  vec3 void_ = vec3(6.,8.,14.)/255., cool = vec3(157.,184.,232.)/255.;
  // the sheet's surface: slow, shallow ripple (rolled glass), as a refraction offset
  vec2 q = uv*vec2(2.6,1.6) + vec2(T*.012, -T*.007);
  float a = fbm(q), bx = fbm(q+vec2(.02,0.)), by = fbm(q+vec2(0.,.02));
  vec2 ruv = uv + vec2(a-bx, a-by)*.42;
  // the room's light, seen through it: a tall window at the right, soft through the frost, a glow off the floor
  float win = smoothstep(0.,.12, ruv.x-.70)*smoothstep(0.,.10, 1.03-ruv.x)*smoothstep(0.,.16, ruv.y-.06)*smoothstep(0.,.18, .86-ruv.y);
  win *= .75 + .35*ruv.y;
  float floorg = smoothstep(.0,.5, .26-ruv.y);
  float L = win*.40 + floorg*.20;
  // the sheets ahead: lit glass edges deeper in the room, seen through the near sheet
  float edges = 0.;
  if (E1 > 0.) { float d = abs(ruv.x*R.x - E1); edges += exp(-d*d/60.)*.42 + exp(-d/90.)*.11; }
  if (E2 > 0.) { float d = abs(ruv.x*R.x - E2); edges += (exp(-d*d/60.)*.42 + exp(-d/90.)*.11)*.6; }
  vec3 col = void_ + cool*L + cool*edges;
  // the near sheet brightens towards its own edge at x = 54: light caught inside the glass
  float e = exp(-max(px.x-54.,0.)/120.); col += cool*e*.30*(.6+L);
  // frost: fine grain, stronger where there is light to scatter
  float g = fbm(px*.95)*.07 - .035; col += g*(.35+L*1.4);
  if (M > .5) col = ink(col);
  gl_FragColor = vec4(col, 1.);
}
"""

# Z: a closed door of smoked glass across the whole view. The light is a slit at its edge, where the
# brink stands; it falls off across the door, catches the door's bevel, and widens as you go.
GLSL_Z = GLSL_HEAD + """
void main(){
  vec2 uv = gl_FragCoord.xy / R; vec2 px = vec2(uv.x*R.x, (1.-uv.y)*R.y);
  vec3 void_ = vec3(6.,8.,14.)/255., cool = vec3(196.,208.,236.)/255., amber = vec3(232.,176.,90.)/255.;
  float brink = 1368., edge = brink - W;
  float g = fbm(px*.8)*.05 - .025;
  vec3 col = void_;
  if (px.x < edge) {
    float d = edge - px.x;
    float I = W > 0. ? .12 + .62*sqrt(min(W,160.)/160.) : 0.;
    float sig = 48. + W*.9;
    float E = I / (1. + (d*d)/(sig*sig)) + .06*I / (1. + (d*d)/360000.);
    float amb = .016 + .022*(1.-uv.y);                       // the door is just there, even unlit
    float rim = exp(-pow((d-3.5)/3.2, 2.)) * (W > 0. ? .95 : .18); // the bevel, lit from behind
    col += cool*(E*.85 + amb) + cool*rim;
    col += cool*(fbm(px*.0035 + vec2(T*.01, 0.))-.5)*.03;  // rolled-glass variation
    col += g*(.5 + E*2.5);
  } else if (px.x < brink) {
    float t = (px.x-edge)/max(W,1.);
    col = cool*(.72 + .2*t) + g*.6;                           // the opening: light, and only light
  } else {
    col = vec3(3.,4.,9.)/255. + cool*exp(-(px.x-brink)/5.)*.22; // the jamb
  }
  float bl = smoothstep(2.4, .5, abs(px.x - brink + 1.));
  vec3 bc = M > .5 ? vec3(85.,98.,138.)/255. : amber;
  if (M > 1.5) bl *= step(.5, fract(px.y/18.));
  col = mix(col, bc, bl);
  if (M > .5) col = mix(col, ink(col), .6);
  gl_FragColor = vec4(col, 1.);
}
"""

# AA: the glass is the floor. Polished, nearly black, a pool of light under the form, haze at its far edge.
GLSL_AA = GLSL_HEAD + """
void main(){
  vec2 uv = gl_FragCoord.xy / R; vec2 px = vec2(uv.x*R.x, (1.-uv.y)*R.y);
  vec3 void_ = vec3(6.,8.,14.)/255., cool = vec3(157.,184.,232.)/255.;
  float g = fbm(px*.85)*.04 - .02;
  vec3 col = void_;
  if (px.y > HZ) {
    vec2 c = vec2(.36*R.x, HZ + .30*(R.y-HZ));
    vec2 dd = (px - c) / vec2(560., 150.);
    float pool = exp(-dot(dd,dd))*.10;
    float haze = exp(-(px.y-HZ)/70.)*.035;
    float sheen = (fbm(px*.0028 + vec2(T*.008, 0.))-.5)*.015;
    col += cool*(pool + haze + sheen) + g*.7;
  } else {
    vec2 w = (px - vec2(1180., 140.)) / vec2(560., 320.);
    col += cool*exp(-length(w))*.075 + g*.4;
  }
  if (M > .5) col = ink(col);
  gl_FragColor = vec4(col, 1.);
}
"""

GL_JS = """
(function () {
  var SRC = { y: %s, z: %s, aa: %s };
  var V = 'attribute vec2 p;void main(){gl_Position=vec4(p,0.,1.);}';
  var still = matchMedia('(prefers-reduced-motion: reduce)').matches;
  document.querySelectorAll('canvas.gl').forEach(function (c) {
    var gl = c.getContext('webgl', { antialias: false, alpha: false, preserveDrawingBuffer: true });
    var host = c.closest('.scene, .stage');
    if (!gl) { host.classList.add('nogl'); return; }
    c.width = 1440; c.height = 900;
    function sh(t, s) { var o = gl.createShader(t); gl.shaderSource(o, s); gl.compileShader(o); return o; }
    var P = gl.createProgram(); gl.attachShader(P, sh(gl.VERTEX_SHADER, V)); gl.attachShader(P, sh(gl.FRAGMENT_SHADER, SRC[c.dataset.fx])); gl.linkProgram(P);
    if (!gl.getProgramParameter(P, gl.LINK_STATUS)) { host.classList.add('nogl'); return; }
    gl.useProgram(P);
    var b = gl.createBuffer(); gl.bindBuffer(gl.ARRAY_BUFFER, b); gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1,-1, 1,-1, -1,1, 1,1]), gl.STATIC_DRAW);
    var a = gl.getAttribLocation(P, 'p'); gl.enableVertexAttribArray(a); gl.vertexAttribPointer(a, 2, gl.FLOAT, false, 0, 0);
    var U = {}; ['R','T','M','W','E1','E2','HZ'].forEach(function (k) { U[k] = gl.getUniformLocation(P, k); });
    gl.viewport(0, 0, 1440, 900); gl.uniform2f(U.R, 1440, 900);
    var v = { M: +c.dataset.m || 0, W: +c.dataset.w || 0, E1: +c.dataset.e1 || 0, E2: +c.dataset.e2 || 0, HZ: +c.dataset.hz || 0 };
    var t0 = performance.now();
    function draw() { gl.uniform1f(U.T, still ? 0 : (performance.now() - t0) / 1000); for (var k in v) gl.uniform1f(U[k], v[k]); gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4); }
    c.set = function (k, x) { v[k] = x; if (still) draw(); };
    draw();
    if (still) return;
    var on = true;
    if ('IntersectionObserver' in window) new IntersectionObserver(function (e) { on = e[0].isIntersecting; }).observe(c);
    (function loop() { if (on) draw(); requestAnimationFrame(loop); })();
  });
})();
"""


def gl_script():
    import json
    return '<script>' + GL_JS % (json.dumps(GLSL_Y), json.dumps(GLSL_Z), json.dumps(GLSL_AA)) + '</script>'


def page(title, css, body, script=''):
    return (f'<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            f'<title>{title}</title>\n<style>{BASE}{css}</style>\n</head>\n<body>\n\n{body}\n\n{script}\n</body>\n</html>\n')


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


def rail(passed, cur, ahead):
    li = ''.join(f'<li class="done">{p}</li>' for p in passed) + f'<li class="now" aria-current="step">{cur}</li>' + ''.join(f'<li class="ahead">{a}</li>' for a in ahead)
    return f'<ol class="rail" aria-label="steps">{li}</ol>'


DIGITS_417 = '<span class="digits">417<span class="blank">···</span></span><span class="caret"></span>'
DIGITS_NONE = '<span class="digits"><span class="blank">······</span></span><span class="caret"></span>'


# ---------------------------------------------------------------- the eight scenes, as content (round 10's copy)
def scenes_for(D):
    S = []
    L, N = D.letter, D.name
    tag = lambda i: f'{L.upper()} · {N} · scene {i} · {SCENES[i-1][1]}'
    sid = lambda k: f'{L}-{k}'
    FROM = f'Connecting from <span class="ip">{IP}</span>.'
    signin_fields = '<div class="fields">' + fld('username', inp('user', 'ada', 'username'), 'live') + fld('password', inp('pass', '', 'password', 'password', live=True), 'live') + '</div>'
    signin_alts = [('Use a passkey', ''), ('Sign in with SSO', 'quiet')]

    d = D.door(f'sign in · step 1 of 2 · {DAY} · {NOW}', 'Sign in', FROM, signin_fields, acts('Sign in', signin_alts))
    S.append(scene(sid('signin'), f'{L.upper()}, {N}: sign in', chrome() + D.hall(d, 'signin'), tag(1), 'g ' + L))

    d = D.door(f'sign in · step 2 of 2 · {DAY} · 09:18:09', 'Enter your authentication code',
               'Enter the six-digit code from your authenticator app.',
               '<div class="fields one">' + fld('authentication code', DIGITS_417, 'live', 'This code is valid for another 19 s.') + '</div>',
               acts('Continue', [('Use a recovery code', 'quiet')], 'Last sign-in: Thu 13 Nov, 09:41'))
    S.append(scene(sid('factor'), f'{L.upper()}, {N}: second factor', chrome() + D.hall(d, 'factor'), tag(2), 'g ' + L))

    d = D.door(f'first run · step 1 of 3 · {DAY} · {NOW}', 'Create the first administrator',
               'No accounts exist yet. Enter the setup code printed in the server log at startup, then choose a username and password. The code expires at 09:27.',
               f'<div class="log">09:12:04 birdcage {VER} · no accounts · <b>setup code {SETUP}</b> · valid until 09:27</div>'
               + '<div class="fields">' + fld('setup code', f'<span class="mono">{SETUP}</span>', 'live', 'Printed in the server log')
               + fld('username', inp('user', 'ada', 'username for the first administrator'), 'live', 'Lower-case letters, digits, dots and dashes')
               + fld('password', inp('pass', '••••••••••••••', 'password', 'password'), 'live', 'At least 12 characters')
               + fld('confirm password', inp('pass2', '•••••••', 'confirm password', 'password', live=True), 'live') + '</div>',
               acts('Create administrator', [('Sign in with SSO instead', 'quiet')]), 'tall')
    S.append(scene(sid('firstrun'), f'{L.upper()}, {N}: first run', chrome() + D.hall(d, 'firstrun'), tag(3), 'g ' + L))

    inner = ('<div class="two">' + qr_svg(D.qr) + '<div class="fields one wide">'
             + fld('key', f'<span class="mono key">{KEY}</span>', 'set', 'Account birdcage:ada · time-based · 6 digits · 30 s')
             + fld('code from the app', DIGITS_NONE, 'live') + '</div></div>')
    d = D.door(f'first run · step 2 of 3 · {DAY} · 09:18:14', 'Set up an authenticator app',
               'Password accounts require a second factor. Scan the QR code or enter the key in an authenticator app, then enter the code it shows. A passkey can be added later in settings.',
               inner, acts('Confirm', [], 'The key is shown once.'), 'wide')
    S.append(scene(sid('enrol'), f'{L.upper()}, {N}: enrol an authenticator', chrome() + D.hall(d, 'enrol'), tag(4), 'g ' + L))

    codes = '<div class="codes">' + ''.join(f'<div><small>{i+1:02d}</small>{c}</div>' for i, c in enumerate(RECOVERY)) + '</div>'
    d = D.door(f'first run · step 3 of 3 · {DAY} · 09:18:41', 'Save your recovery codes',
               'Each code can be used once in place of your authenticator app. Store them somewhere safe, away from this computer. They will not be shown again.',
               codes, acts('Continue', [('Copy', ''), ('Download', ''), ('Print', 'quiet')], '10 codes · none used'), 'wide')
    S.append(scene(sid('codes'), f'{L.upper()}, {N}: recovery codes shown once', chrome() + D.hall(d, 'codes'), tag(5), 'g ' + L))

    d = D.door(f'sign in · session expired · {DAY} · {NOW}', 'Session expired',
               'Your session expired at 08:52 after an hour of inactivity. '
               'Enter your password to continue. A full sign-in, including your authentication code, is required again by <b>Sunday 07:31</b>.',
               '<div class="fields one">' + fld('password', inp('pass', '', 'password', 'password', live=True), 'live', 'A passkey can also be used.') + '</div>',
               acts('Continue', [('Sign in as a different user', 'quiet')]))
    S.append(scene(sid('timeout'), f'{L.upper()}, {N}: timed out, over the dimmed dashboard', D.hall(d, 'timeout'), tag(6), 'g ' + L))

    d = D.door(f'sign in · step 1 of 2 · {DAY} · 09:18:07', 'Sign in', FROM,
               signin_fields + '<div class="said"><b>Incorrect username or password.</b><span>4 attempts left</span></div>',
               acts('Sign in', signin_alts), 'refused')
    S.append(scene(sid('refused'), f'{L.upper()}, {N}: refused, wrong password', chrome() + D.hall(d, 'refused'), tag(7), 'g ' + L))

    d = D.door(f'sign in · paused · {DAY} · 09:18:48', 'Too many attempts',
               f'Sign-in for this username from <span class="ip">{IP}</span> is paused after 5 failed attempts. Try again at <b>09:23</b>.',
               '<div class="wait"><b>4:12</b><span>until 09:23:00</span></div>'
               + '<div class="fields">' + fld('username', 'ada', 'off') + fld('password', '', 'off', '5 failed attempts between 09:18:07 and 09:18:48') + '</div>',
               acts('Sign in', signin_alts, 'Passkey and SSO sign-in are not paused.', 'go off'), 'locked')
    S.append(scene(sid('locked'), f'{L.upper()}, {N}: too many tries, wait', chrome() + D.hall(d, 'locked'), tag(8), 'g ' + L))
    return S


# ---------------------------------------------------------------- the form, with no card around it: type and rules on glass
CONTENT = """
  .door { position: relative; z-index: 2; display: flex; flex-direction: column; }
  .door .step { font: 600 9.5px var(--mono); letter-spacing: .18em; color: var(--ink-3); text-transform: uppercase; }
  .door h1 { margin: 12px 0 14px; font: 400 60px/1.04 var(--sans); letter-spacing: -.025em; color: var(--ink); }
  .door.tall h1 { font-size: 44px; } .door.wide h1 { font-size: 52px; }
  .door .sub { margin: 0; font: 16px/1.55 var(--sans); color: var(--ink-2); max-width: 58ch; }
  .door.tall .sub { font-size: 14.5px; }
  .door .sub b { color: var(--ink); font-weight: 600; } .door .sub .ip { color: var(--ink); font-size: 15px; }
  .door .fields { margin-top: 30px; display: grid; grid-template-columns: 1fr 1fr; gap: 22px 48px; }
  .door.tall .fields { margin-top: 20px; gap: 14px 48px; }
  .door .fields.one { grid-template-columns: 1fr; max-width: 440px; } .door .fields.wide { max-width: none; }
  .door .fld label { display: block; font: 600 9.5px var(--mono); letter-spacing: .18em; color: var(--ink-3); text-transform: uppercase; margin-bottom: 4px; }
  .door .fld .box { height: 46px; display: flex; align-items: center; font: 24px var(--sans); color: var(--ink); border-bottom: 1px solid var(--hair-2); }
  .door .fld.live .box { border-bottom-color: rgba(160,185,230,.45); }
  .door .fld.live:has(.caret) .box { border-bottom: 1px solid var(--accent); box-shadow: 0 1px 0 rgba(157,184,232,.35), 0 14px 26px -16px rgba(157,184,232,.6); }
  .door .fld .box input { width: 100%; font: inherit; }
  .door .fld .box .mono { font: 500 20px var(--mono); letter-spacing: .03em; }
  .door .fld .box .digits { font: 500 30px var(--mono); letter-spacing: .5em; } .door .fld .box .digits .blank { color: var(--ink-3); }
  .door .fld .note { margin-top: 7px; font: 11.5px var(--sans); color: var(--ink-3); } .door .fld .note.ok { color: var(--ok); }
  .door .fld.set .box { color: var(--ink-2); } .door .fld.off .box { color: var(--ink-3); border-bottom-style: dashed; border-bottom-color: var(--ink-3); }
  .door .acts { display: flex; align-items: center; gap: 14px; margin-top: 40px; }
  .door .acts .sp { flex: 1; } .door .acts .meta { font: 11.5px var(--mono); color: var(--ink-3); }
  .door .go { height: 44px; padding: 0 26px; border-radius: 999px; background: var(--accent); color: var(--void); font-weight: 600; font-size: 14px; white-space: nowrap;
    box-shadow: 0 0 0 1px rgba(157,184,232,.55), 0 16px 36px -14px rgba(157,184,232,.75); }
  .door .go.off { background: transparent; color: var(--ink-3); box-shadow: none; border: 1px dashed var(--ink-3); }
  .door .alt { height: 42px; padding: 0 20px; border-radius: 999px; border: 1px solid var(--hair-2); color: var(--ink-2); font-size: 13.5px; white-space: nowrap; }
  .door .alt.quiet { color: var(--ink-3); border-color: transparent; padding: 0 8px; }
  .door .codes { margin-top: 26px; display: grid; grid-template-columns: repeat(5, 1fr); gap: 20px 28px; }
  .door .codes div { font: 500 22px var(--mono); color: var(--ink); letter-spacing: .04em; padding: 8px 0 12px; border-bottom: 1px solid var(--hair-2); }
  .door .codes div small { display: block; font: 10px var(--mono); color: var(--ink-3); letter-spacing: .1em; margin-bottom: 8px; }
  .door .two { display: grid; grid-template-columns: auto 1fr; gap: 44px; margin-top: 26px; align-items: start; }
  .door .qr { display: block; background: #fff; padding: 10px; border-radius: 4px; } .door .qr rect { fill: #06080e; }
  .door .wait { margin-top: 22px; display: flex; align-items: baseline; gap: 16px; }
  .door .wait b { font: 400 64px/1 var(--mono); color: var(--ink); letter-spacing: -.02em; } .door .wait span { font: 13px var(--sans); color: var(--ink-2); }
  .door .log { margin-top: 18px; font: 12px var(--mono); color: var(--ink-3); padding: 7px 12px; border-left: 2px solid var(--hair-2); }
  .door .log b { color: var(--ink); font-weight: 600; }
  .door .said { margin-top: 18px; padding: 8px 14px; border-left: 2px solid var(--ink); font: 13.5px var(--sans); color: var(--ink); display: flex; gap: 14px; align-items: baseline; }
  .door .said span { font: 11.5px var(--mono); color: var(--ink-2); }
  .door.refused h1, .door.locked h1 { color: var(--ink-2); }
  .door.locked .go.off { pointer-events: none; }
  /* the step rail */
  .rail { position: absolute; z-index: 3; margin: 0; padding: 0; list-style: none; display: flex; gap: 26px; font: 600 9.5px var(--mono); letter-spacing: .18em; text-transform: uppercase; color: var(--ink-3); white-space: nowrap; }
  .rail li::before { content: ''; display: inline-block; width: 6px; height: 6px; border-radius: 50%; border: 1px solid currentColor; margin-right: 9px; vertical-align: 1px; }
  .rail .now { color: var(--ink); } .rail .now::before { background: currentColor; }
  .rail .done { color: var(--ok); } .rail .done::before { content: '✓'; border: 0; width: auto; height: auto; font-size: 10px; vertical-align: 0; }
  .rail .ahead::before { border-style: dashed; }
"""

NOGL = """
  .nogl.y { background: radial-gradient(60% 70% at 82% 32%, rgba(157,184,232,.26), transparent 70%), linear-gradient(to top, rgba(157,184,232,.08), transparent 30%), var(--void); }
  .nogl.z { background: linear-gradient(90deg, var(--void) 55%, rgba(157,184,232,.12) 93%, rgba(196,208,236,.9) 95%, #03040a 95.1%); }
  .nogl.aa { background: linear-gradient(to bottom, var(--void) 71%, rgba(157,184,232,.07) 71.2%, var(--void)); }
"""


class Dir:
    letter = ''
    name = ''
    qr = 176

    def door(self, step, title, sub, inner, actions, cls=''):
        return (f'<div class="door {cls}"><div class="step">{step}</div><h1>{title}</h1><p class="sub">{sub}</p>'
                f'{inner}{actions}</div>')


# ================================================================ Y · through the glass
# You stand at a sheet of rolled glass taller and wider than the view; its lit edge is at the gutter.
# The form is set on the glass, large, with no box round it. Behind, a lit room with nothing in it
# but light, and the edges of the sheets still to pass, deeper in. Each step walks you through the
# sheet you are at; the one behind you shows as a green edge at the very left.
Y_CSS = CONTENT + NOGL + """
  .y .edge { position: absolute; top: -40px; bottom: -40px; left: 54px; width: 10px; z-index: 2; pointer-events: none;
    background: linear-gradient(90deg, transparent, rgba(157,184,232,.5) 35%, rgba(255,255,255,.9) 50%, rgba(157,184,232,.5) 65%, transparent);
    box-shadow: 0 0 44px 8px rgba(157,184,232,.16); }
  .y .edge.done { left: var(--x); width: 4px; background: linear-gradient(90deg, transparent, rgba(55,179,100,.9), transparent); box-shadow: 0 0 26px 3px rgba(55,179,100,.22); }
  .y .edge.ink { background: linear-gradient(90deg, transparent, rgba(151,164,196,.55) 50%, transparent); box-shadow: none; width: 6px; }
  .y .edge.dashed { width: 2px; left: 58px; background: repeating-linear-gradient(to bottom, var(--ink-3) 0 14px, transparent 14px 26px); box-shadow: none; }
  .y .rail { left: 110px; top: 74px; }
  .y .col { position: absolute; left: 110px; top: 0; bottom: 0; width: 780px; display: flex; flex-direction: column; justify-content: center; padding: 60px 0 40px; }
  .y .col.wide { width: 1100px; }
  .y .ver { right: auto; left: 110px; top: 24px; }
  .y .door .acts { flex-wrap: wrap; } .y .door .acts .sp { display: none; } .y .door .acts .meta { flex-basis: 100%; margin-top: 10px; } .y .col.tall { padding-top: 110px; }
  .y .door h1 { font-size: 72px; } .y .door.wide h1 { font-size: 56px; } .y .door.tall h1 { font-size: 46px; }
  .y .frost { position: absolute; inset: 0; backdrop-filter: blur(12px) saturate(.8); -webkit-backdrop-filter: blur(12px) saturate(.8); background: rgba(6,8,14,.55); }
  .y canvas.gl.over { opacity: .5; mix-blend-mode: screen; }
"""


class Y(Dir):
    letter, name = 'y', 'through the glass'

    def hall(self, door, key):
        passed, cur, ahead = STEPS[key]
        wide = key in WIDE
        xs = ([1335, 1400] if wide else [1060, 1250])[:len(ahead)]
        mood = MOOD.get(key, 0)
        e = ' '.join(f'data-e{i+1}="{x}"' for i, x in enumerate(xs))
        out = ''
        if key == 'timeout':
            out += shell('08:52:10') + '<div class="frost" aria-hidden="true"></div>'
            out += f'<canvas class="gl over" data-fx="y" data-m="0" aria-hidden="true"></canvas>'
        else:
            out += f'<canvas class="gl" data-fx="y" data-m="{mood}" {e} aria-hidden="true"></canvas>'
        out += ''.join(f'<div class="edge done" style="--x:{10 + i*16}px" aria-hidden="true"></div>' for i in range(len(passed)))
        out += f'<div class="edge cur {["", "ink", "dashed"][mood]}" aria-hidden="true"></div>'
        out += rail(passed, cur, ahead)
        cls = 'wide' if wide else ('tall' if key in TALL else '')
        out += f'<div class="col {cls}">{door}</div>'
        return out


# ================================================================ Z · ajar
# The whole view is a closed door of smoked glass. The one light is the slit at its edge, where the
# brink stands at x = 1368; it widens with each step and the door's bevel catches it. The form sits
# on the door, against the light. A refusal takes the light away; a pause leaves the brink dashed.
Z_CSS = CONTENT + NOGL + """
  .z .rail { left: 720px; top: 74px; }
  .z .ver { right: auto; left: 22px; top: 52px; }
  .z .col { position: absolute; left: 720px; top: 0; bottom: 0; width: 540px; display: flex; flex-direction: column; justify-content: center; padding: 60px 0 40px; }
  .z .col.wide { left: 340px; width: 920px; }
  .z .door h1 { font-size: 54px; } .z .door.tall h1 { font-size: 40px; } .z .door.wide h1 { font-size: 50px; }
  .z .door .sub { font-size: 15px; }
  .z .door .fields { gap: 20px 36px; }
  .z .door .fld .box { border-image: linear-gradient(90deg, var(--hair-2), rgba(160,185,230,.6)) 1; }
  .z .door .fld.live:has(.caret) .box { border-image: linear-gradient(90deg, rgba(157,184,232,.5), #fff) 1; box-shadow: 0 14px 26px -16px rgba(157,184,232,.6); }
  .z .door .fld.off .box { border-image: none; }
  .z .door .codes { grid-template-columns: repeat(5, 1fr); } .z .door .codes div { font-size: 20px; }
  .z .door .acts { flex-wrap: wrap; } .z .door .acts .sp { display: none; } .z .door .acts .meta { flex-basis: 100%; margin-top: 10px; }
  .z .frost { position: absolute; left: 0; top: 0; bottom: 0; width: 1264px; backdrop-filter: blur(9px); -webkit-backdrop-filter: blur(9px); background: rgba(6,8,14,.80); }
  .z .jamb { position: absolute; left: 1368px; top: 0; bottom: 0; right: 0; background: #03040a; }
  .z canvas.gl.over { opacity: .9; mix-blend-mode: screen; clip-path: inset(0 176px 0 0); }
  .z .brinkline { position: absolute; left: 1367px; top: 0; bottom: 0; width: 2px; background: var(--now); z-index: 2; }
"""

# how far the door stands open in each scene, in px, at the brink
Z_W = {'signin': 6, 'factor': 72, 'firstrun': 6, 'enrol': 48, 'codes': 108, 'timeout': 104, 'refused': 0, 'locked': 0}


class Z(Dir):
    letter, name = 'z', 'ajar'
    qr = 168

    def hall(self, door, key):
        passed, cur, ahead = STEPS[key]
        wide = key in WIDE
        mood = MOOD.get(key, 0)
        out = ''
        if key == 'timeout':
            out += shell('08:52:10') + '<div class="frost" aria-hidden="true"></div><div class="jamb" aria-hidden="true"></div>'
            out += f'<canvas class="gl over" data-fx="z" data-m="0" data-w="{Z_W[key]}" aria-hidden="true"></canvas><div class="brinkline" aria-hidden="true"></div>'
        else:
            out += f'<canvas class="gl" data-fx="z" data-m="{mood}" data-w="{Z_W[key]}" aria-hidden="true"></canvas>'
        out += rail(passed, cur, ahead).replace('class="rail"', 'class="rail" style="left:340px"' if wide else 'class="rail"')
        cls = 'wide' if wide else ('tall' if key in TALL else '')
        out += f'<div class="col {cls}">{door}</div>'
        return out


# ================================================================ AA · the floor
# The glass is under you: a polished black floor with a horizon at y = 640. The form stands in the
# room with nothing round it and is reflected in the floor; the steps passed stand behind you to the
# left as green-edged slabs, the steps ahead to the right, dashed. Everything standing is mirrored.
HZ = 640
AA_CSS = CONTENT + NOGL + """
  .aa .rail { left: 130px; top: 74px; }
  .aa .stand, .aa .mirror { position: absolute; left: 0; right: 0; top: 0; height: 640px; perspective: 1500px; perspective-origin: 50% 100%; }
  .aa .mirror { top: 640px; transform: scaleY(-1); pointer-events: none; }
  .aa .mirror.near { filter: blur(1.2px); mask-image: linear-gradient(to top, rgba(0,0,0,.30), rgba(0,0,0,.12) 90px, transparent 170px); -webkit-mask-image: linear-gradient(to top, rgba(0,0,0,.30), rgba(0,0,0,.12) 90px, transparent 170px); }
  .aa .mirror.far { filter: blur(5px); mask-image: linear-gradient(to top, transparent 60px, rgba(0,0,0,.14) 150px, transparent 300px); -webkit-mask-image: linear-gradient(to top, transparent 60px, rgba(0,0,0,.14) 150px, transparent 300px); }
  .aa .col { position: absolute; left: 130px; bottom: 0; width: 780px; }
  .aa .col.wide { width: 1160px; }
  .aa .door { padding-bottom: 2px; }
  .aa .door h1 { font-size: 66px; } .aa .door.tall h1 { font-size: 40px; } .aa .door.wide h1 { font-size: 54px; }
  .aa .door.tall .sub { font-size: 14px; } .aa .door.tall .fields { margin-top: 14px; gap: 8px 48px; } .aa .door.tall .fld .box { height: 40px; font-size: 20px; } .aa .door.tall .log { margin-top: 12px; } .aa .door.tall .acts { margin-top: 26px; }
  .aa .door .acts { margin-top: 36px; }
  .aa .slab { position: absolute; bottom: 0; left: var(--x); width: 60px; height: 330px; border-radius: 5px; display: flex; align-items: center; justify-content: center;
    transform: rotateY(var(--ry)); transform-origin: center bottom;
    background: linear-gradient(160deg, rgba(160,185,230,.12), rgba(160,185,230,.03) 55%, rgba(160,185,230,.08));
    box-shadow: inset 0 1px 0 rgba(255,255,255,.14), inset 0 -1px 0 rgba(0,0,0,.5), 0 0 0 1px var(--hair-2); }
  .aa .slab span { writing-mode: sideways-lr; font: 500 9.5px var(--mono); letter-spacing: .22em; text-transform: uppercase; color: var(--ink-3); white-space: nowrap; }
  .aa .slab.done { box-shadow: inset 0 1px 0 rgba(255,255,255,.14), 0 0 0 1px rgba(55,179,100,.6), 0 0 48px -8px rgba(55,179,100,.35); }
  .aa .slab.done span { color: var(--ok); }
  .aa .slab.done::before { content: '✓'; position: absolute; top: 14px; left: 0; right: 0; text-align: center; font: 700 12px var(--mono); color: var(--ok); }
  .aa .slab.ahead { background: none; box-shadow: none; border: 1px dashed var(--ink-3); }
  .aa .slab.ahead span { color: var(--ink-3); }
  .aa .dimfloor { position: absolute; inset: 0; backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px); background: rgba(6,8,14,.5); }
  .aa canvas.gl.over { opacity: .8; mix-blend-mode: screen; }
  .aa.ink .slab, .aa.ink .door { filter: saturate(.6); }
"""


class AA(Dir):
    letter, name = 'aa', 'the floor'

    def hall(self, door, key):
        passed, cur, ahead = STEPS[key]
        wide = key in WIDE
        mood = MOOD.get(key, 0)
        px = [40, 86] if not wide else [20, 62]
        ax = [1330] if len(ahead) < 2 else [1270, 1345]
        slabs = ''.join(f'<div class="slab done" style="--x:{px[i]}px;--ry:{58 - i*10}deg" aria-label="passed: {p}"><span>{p}</span></div>' for i, p in enumerate(passed))
        slabs += ''.join(f'<div class="slab ahead" style="--x:{ax[i]}px;--ry:{-48 + i*8}deg" aria-label="ahead: {a}"><span>{a}</span></div>' for i, a in enumerate(ahead))
        cls = 'wide' if wide else ('tall' if key in TALL else '')
        stand = f'{slabs}<div class="col {cls}">{door}</div>'
        out = ''
        if key == 'timeout':
            out += shell('08:52:10') + '<div class="dimfloor" aria-hidden="true"></div>'
            out += f'<canvas class="gl over" data-fx="aa" data-hz="{HZ}" data-m="0" aria-hidden="true"></canvas>'
        else:
            out += f'<canvas class="gl" data-fx="aa" data-hz="{HZ}" data-m="{mood}" aria-hidden="true"></canvas>'
        out += rail(passed, cur, ahead)
        mirror = stand.replace('aria-label', 'data-l').replace('<input ', '<input tabindex="-1" ').replace('aria-current="step"', '')
        out += f'<div class="stand">{stand}</div><div class="mirror near" aria-hidden="true" inert>{mirror}</div><div class="mirror far" aria-hidden="true" inert>{mirror}</div>'
        return out


# ---------------------------------------------------------------- motion pages
# One 12 s loop: step one is passed, step two arrives and is passed, then the hand-over: the last
# glass goes and the real shell's first view is there. Reduced motion: a still of step two.
MOTION_BASE = """
  .stage { position: relative; width: 1440px; height: 900px; margin: 0 auto; overflow: hidden; background: var(--void); }
  .stage .cap { position: absolute; left: 50%; transform: translateX(-50%); bottom: 16px; white-space: nowrap; padding: 6px 14px; border-radius: 999px; background: var(--void); text-align: center; font: 12.5px var(--sans); color: var(--ink-2); z-index: 8; }
  .stage .still { position: absolute; top: 18px; left: 50%; transform: translateX(-50%); font: 10px var(--mono); letter-spacing: .14em; text-transform: uppercase; color: var(--ink-3); z-index: 5; }
  .stage .shell.into { opacity: 0; z-index: 6; background: var(--void); }
  .stage .shell.into svg.band { clip-path: inset(0 0 0 0); }
  .stage .m1 { opacity: 0; } .stage .m2 { opacity: 1; }
  @media (prefers-reduced-motion: no-preference) {
    .stage .still { display: none; }
    .stage .shell.into { animation: m-shell 12s infinite; } @keyframes m-shell { 0%, 64% { opacity: 0; } 74%, 94% { opacity: 1; } 100% { opacity: 0; } }
    .stage .shell.into svg.band { animation: m-lines 12s cubic-bezier(.4,0,.2,1) infinite; } @keyframes m-lines { 0%, 68% { clip-path: inset(0 100% 0 0); } 84%, 100% { clip-path: inset(0 0 0 0); } }
    .stage .cap, .stage .chrome { animation: m-chrome 12s infinite; } @keyframes m-chrome { 0%, 66% { opacity: 1; } 72%, 94% { opacity: 0; } 100% { opacity: 1; } }
    /* the rail: step one current, then passed */
    .stage .m1 { animation: m-r1 12s infinite; } @keyframes m-r1 { 0%, 26% { opacity: 1; } 30%, 100% { opacity: 0; } }
    .stage .m2 { animation: m-r2 12s infinite; } @keyframes m-r2 { 0%, 26% { opacity: 0; } 30%, 100% { opacity: 1; } }
  }
"""


def motion_page(D, css, body, cap, extra_js=''):
    return page(f'Birdcage · round 11 · {D.letter.upper()} · {D.name} · motion',
                css + MOTION_BASE,
                f'<div class="stage g {D.letter}" role="region" aria-label="{D.letter.upper()}, {D.name}: the motion, step to step, then the hand-over into the cage">'
                f'<div class="still">reduced motion · still</div><div class="chrome">{chrome()}</div>{body}'
                f'{shell("09:18:12", cls="into")}'
                f'<div class="cap">{cap}</div></div>', gl_script() + extra_js)


def door_one(D):
    return D.door(f'sign in · step 1 of 2 · {DAY} · {NOW}', 'Sign in', f'Connecting from <span class="ip">{IP}</span>.',
                  '<div class="fields">' + fld('username', 'ada', 'live') + fld('password', '<span>••••••••••••</span>', 'live') + '</div>',
                  acts('Sign in', [('Use a passkey', ''), ('Sign in with SSO', 'quiet')]))


def door_two(D):
    return D.door(f'sign in · step 2 of 2 · {DAY} · 09:18:09', 'Enter your authentication code',
                  'Enter the six-digit code from your authenticator app.',
                  '<div class="fields one">' + fld('authentication code', '<span class="digits">417 926</span>', 'live', 'accepted') + '</div>',
                  acts('Continue', [('Use a recovery code', 'quiet')], 'Last sign-in: Thu 13 Nov, 09:41'))


def rails(cls=''):
    r1 = rail([], 'Password', ['Authentication code']).replace('class="rail"', f'class="rail m1 {cls}"')
    r2 = rail(['Password'], 'Authentication code', []).replace('class="rail"', f'class="rail m2 {cls}"')
    return r1 + r2


# Y: you walk through sheet one; sheet two is already there, deeper, and comes into focus.
Y_MOTION = """
  .y .sheet { position: absolute; inset: 0; transform-origin: 38% 50%; }
  .y .sheet .col { padding-bottom: 40px; }
  .y .s1 { opacity: 0; } .y .s2 { opacity: 1; }
  .y .edge.done.p1 { opacity: 1; }
  @media (prefers-reduced-motion: no-preference) {
    .y .s1 { animation: y-s1 12s cubic-bezier(.4,0,.2,1) infinite; }
    @keyframes y-s1 { 0% { opacity: 0; transform: scale(.86); filter: blur(6px); } 6%, 22% { opacity: 1; transform: none; filter: none; } 30%, 100% { opacity: 0; transform: scale(1.5); filter: blur(14px); } }
    .y .s2 { animation: y-s2 12s cubic-bezier(.4,0,.2,1) infinite; }
    @keyframes y-s2 { 0%, 22% { opacity: 0; transform: scale(.80); filter: blur(8px); } 34%, 56% { opacity: 1; transform: none; filter: none; } 64%, 100% { opacity: 0; transform: scale(1.5); filter: blur(14px); } }
    .y .edge.done.p1 { animation: y-p1 12s infinite; } @keyframes y-p1 { 0%, 28% { opacity: 0; } 34%, 66% { opacity: 1; } 72%, 100% { opacity: 0; } }
  }
"""

# Z: the slit widens as each step is passed; at the end the whole door swings away on its left hinge
# and the shell is what was behind it. The slit's width is driven in JS so the shader follows the loop.
Z_MOTION = """
  .z .doorlayer { position: absolute; inset: 0; transform-origin: left center; z-index: 5; }
  .z .scenewrap { position: absolute; inset: 0; perspective: 1700px; perspective-origin: 30% 50%; }
  .z .jambm { position: absolute; left: 1368px; top: 0; bottom: 0; right: 0; background: #03040a; z-index: 4; }
  .z .doorlayer canvas.gl { clip-path: inset(0 72px 0 0); }
  .z .d1, .z .d2 { position: absolute; inset: 0; } .z .d1 { opacity: 0; } .z .d2 { opacity: 1; }
  .z .brinkm { position: absolute; left: 1367px; top: 0; bottom: 0; width: 2px; background: var(--now); z-index: 4; }
  @media (prefers-reduced-motion: no-preference) {
    .z .d1 { animation: z-d1 12s cubic-bezier(.4,0,.2,1) infinite; } @keyframes z-d1 { 0% { opacity: 0; transform: translateY(14px); } 6%, 22% { opacity: 1; transform: none; } 28%, 100% { opacity: 0; transform: translateX(-30px); } }
    .z .d2 { animation: z-d2 12s cubic-bezier(.4,0,.2,1) infinite; } @keyframes z-d2 { 0%, 26% { opacity: 0; transform: translateX(40px); } 34%, 56% { opacity: 1; transform: none; } 60%, 100% { opacity: 0; } }
    .z .doorlayer { animation: z-swing 12s cubic-bezier(.55,0,.3,1) infinite; } @keyframes z-swing { 0%, 62% { transform: none; opacity: 1; } 74%, 94% { transform: rotateY(-104deg); opacity: 1; } 95%, 100% { transform: none; opacity: 0; } }
    .z .jambm, .z .brinkm { animation: m-chrome 12s infinite; }
  }
"""

Z_JS = """
<script>
(function () {
  var c = document.querySelector('.stage.z canvas.gl'); if (!c) return;
  var still = matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (still) { if (c.set) c.set('W', 72); return; }
  var t0 = performance.now();
  function ease(x) { return x < .5 ? 2*x*x : 1 - Math.pow(-2*x + 2, 2)/2; }
  function w(t) {
    if (t < .22) return 6;
    if (t < .30) return 6 + 66*ease((t-.22)/.08);
    if (t < .58) return 72;
    if (t < .66) return 72 + 240*ease((t-.58)/.08);
    if (t < .95) return 312;
    return 6;
  }
  (function loop() { var t = ((performance.now() - t0) % 12000) / 12000; if (c.set) c.set('W', w(t)); requestAnimationFrame(loop); })();
})();
</script>
"""

# AA: the form you have finished slides back to the left and becomes a standing slab; the next rises
# out of the depth. At the end the floor's horizon lifts to the band's height and the lines draw.
AA_MOTION = """
  .aa .c1, .aa .c2 { position: absolute; left: 130px; bottom: 0; width: 780px; transform-origin: left bottom; }
  .aa .c1 { opacity: 0; } .aa .c2 { opacity: 1; } .aa .slab.p1 { opacity: 1; }
  .aa .hz { position: absolute; left: 0; right: 0; top: 640px; height: 1px; background: linear-gradient(90deg, transparent, rgba(157,184,232,.35) 15%, rgba(157,184,232,.35) 85%, transparent); z-index: 7; opacity: 0; }
  @media (prefers-reduced-motion: no-preference) {
    .aa .c1 { animation: aa-c1 12s cubic-bezier(.4,0,.2,1) infinite; }
    @keyframes aa-c1 { 0% { opacity: 0; transform: translateZ(-700px) translateX(240px); } 6%, 22% { opacity: 1; transform: none; } 30%, 100% { opacity: 0; transform: translateX(-60px) scale(.3) rotateY(58deg); } }
    .aa .c2 { animation: aa-c2 12s cubic-bezier(.4,0,.2,1) infinite; }
    @keyframes aa-c2 { 0%, 24% { opacity: 0; transform: translateZ(-700px) translateX(240px); } 36%, 56% { opacity: 1; transform: none; } 64%, 100% { opacity: 0; transform: translateX(-60px) scale(.3) rotateY(58deg); } }
    .aa .slab.p1 { animation: aa-p1 12s infinite; } @keyframes aa-p1 { 0%, 28% { opacity: 0; } 34%, 64% { opacity: 1; } 70%, 100% { opacity: 0; } }
    .aa .slab.p2 { animation: aa-p2 12s infinite; } @keyframes aa-p2 { 0%, 26% { opacity: 1; } 32%, 100% { opacity: 0; } }
    .aa canvas.gl, .aa .mirror { animation: m-room 12s infinite; } @keyframes m-room { 0%, 62% { opacity: 1; } 72%, 94% { opacity: 0; } 100% { opacity: 1; } }
    .aa .hz { animation: aa-hz 12s cubic-bezier(.4,0,.2,1) infinite; } @keyframes aa-hz { 0%, 62% { top: 640px; opacity: 0; } 64% { opacity: 1; } 72% { top: 300px; opacity: 1; } 78%, 100% { top: 300px; opacity: 0; } }
  }
"""


def build_motion(D):
    L = D.letter
    d1 = door_one(D)
    d2 = door_two(D)
    if L == 'y':
        body = ('<div class="sheet s1"><canvas class="gl" data-fx="y" data-m="0" data-e1="1060" aria-hidden="true"></canvas>'
                f'<div class="edge cur" aria-hidden="true"></div><div class="col">{d1}</div></div>'
                '<div class="sheet s2"><canvas class="gl" data-fx="y" data-m="0" aria-hidden="true"></canvas>'
                f'<div class="edge cur" aria-hidden="true"></div><div class="col">{d2}</div></div>'
                '<div class="edge done p1" style="--x:10px" aria-hidden="true"></div>' + rails())
        return motion_page(D, Y_CSS + Y_MOTION, body, 'Y · through the glass · motion')
    if L == 'z':
        body = ('<div class="scenewrap"><div class="doorlayer">'
                '<canvas class="gl" data-fx="z" data-m="0" data-w="72" aria-hidden="true"></canvas>'
                f'<div class="d1">{rail([], "Password", ["Authentication code"])}<div class="col">{d1}</div></div>'
                f'<div class="d2">{rail(["Password"], "Authentication code", [])}<div class="col">{d2}</div></div>'
                '</div></div><div class="jambm" aria-hidden="true"></div><div class="brinkm" aria-hidden="true"></div>')
        return motion_page(D, Z_CSS + Z_MOTION, body, 'Z · ajar · motion', Z_JS)
    p1 = '<div class="slab done p1" style="--x:40px;--ry:58deg" aria-label="passed: password"><span>Password</span></div>'
    p2 = '<div class="slab ahead p2" style="--x:1330px;--ry:-48deg" aria-label="ahead: authentication code"><span>Authentication code</span></div>'
    stand = f'{p1}{p2}<div class="c1">{d1}</div><div class="c2">{d2}</div>'
    mirror = stand.replace('aria-label', 'data-l')
    body = (f'<canvas class="gl" data-fx="aa" data-hz="{HZ}" data-m="0" aria-hidden="true"></canvas>' + rails()
            + f'<div class="stand">{stand}</div><div class="mirror near" aria-hidden="true" inert>{mirror}</div><div class="mirror far" aria-hidden="true" inert>{mirror}</div>'
            '<div class="hz" aria-hidden="true"></div>')
    return motion_page(D, AA_CSS + AA_MOTION, body, 'AA · the floor · motion')


def build_dir(D, css):
    return page(f'Birdcage · round 11 · {D.letter.upper()} · {D.name}', css, '\n\n'.join(scenes_for(D)), gl_script())


if __name__ == '__main__':
    for D, css in [(Y(), Y_CSS), (Z(), Z_CSS), (AA(), AA_CSS)]:
        fn = dict((l, f) for l, _, f in DIRS)[D.letter]
        with open(fn, 'w') as f:
            f.write(build_dir(D, css))
        print(fn)
        mf = f'motion-{D.letter}.html'
        with open(mf, 'w') as f:
            f.write(build_motion(D))
        print(mf)
