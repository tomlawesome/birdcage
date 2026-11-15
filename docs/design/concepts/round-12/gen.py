#!/usr/bin/env python3
"""Build the three round-12 prototypes: each one self-contained HTML page (plus dashboard.jpg)."""
import pathlib
here = pathlib.Path(__file__).parent
src = here / 'src'
DIRS = [('ab', 'reeded-glass', 'Reeded glass'), ('ac', 'ribbons', 'Ribbons'), ('ad', 'the-dome', 'The dome')]
T = '''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Birdcage · Sign in · {name}</title>
<style>
{css}
</style></head>
<body class="{cls}" data-state="signin">
<img id="shell" src="dashboard.jpg" alt="" aria-hidden="true">
<canvas id="bg" aria-hidden="true"></canvas>
<div class="brand">BIRD<span>CAGE</span></div>
<main class="door">
<form class="step" id="f-signin" novalidate>
<h1>Sign in</h1>
<label for="username">Username</label><input id="username" autocomplete="username" value="ada" spellcheck="false">
<label for="password">Password</label><input id="password" type="password" autocomplete="current-password">
<p id="err" role="alert" hidden>Incorrect username or password. <span>4 attempts left.</span></p>
<div class="acts"><button class="btn">Sign in</button><a href="#" class="alt">Use a passkey</a><a href="#" class="alt">Single sign-on</a></div>
</form>
<form class="step" id="f-code" novalidate>
<h1>Authentication code</h1>
<p class="sub">Enter the 6-digit code from your authenticator app.</p>
<label for="code" class="vh">Authentication code</label><input id="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="000000">
<div class="acts"><button class="btn">Continue</button><a href="#" class="alt">Use a recovery code</a></div>
</form>
</main>
<nav class="proto" aria-label="Prototype controls"><span>{letter} · {name}</span><a href="#" data-go="signin">1 sign in</a><a href="#" data-go="refused">2 refused</a><a href="#" data-go="code">3 code</a><a href="#" data-go="in">4 enter</a></nav>
<script>
{js}
</script>
</body></html>
'''
for cls, slug, name in DIRS:
    css = (src / 'base.css').read_text() + (src / f'{cls}.css').read_text()
    js = (src / 'base.js').read_text() + (src / f'{cls}.js').read_text()
    out = here / f'direction-{cls}-{slug}.html'
    out.write_text(T.format(name=name, cls=cls, letter=cls.upper(), css=css, js=js))
    print(out.name)
