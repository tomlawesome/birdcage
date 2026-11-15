// The bars: drawn on a canvas so a bar can move. Pulses climb random bars and make them wiggle;
// data-glint on <body> picks how the rest of the bars catch light: drift | ripple | shimmer.
(() => {
  const c = document.querySelector('#bars'), x = c.getContext('2d');
  const MODE = document.body.dataset.glint, STILL = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const q = new URLSearchParams(location.search), FROZEN = q.has('t') ? +q.get('t') : null;
  let seed = 20261115; const rnd = () => { seed |= 0; seed = seed + 0x6D2B79F5 | 0; let t = Math.imul(seed ^ seed >>> 15, 1 | seed); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; };
  const COL = [[57, 135, 229], [25, 158, 112], [232, 176, 90], [215, 106, 158]];
  const GAP = 210, STEP = 46, PULSE = 130, RISE = 2.6;
  let W, H, D, bars = [], pulses = [], ripples = [], next = .6, open = 0, T = 0;
  function size() {
    D = Math.min(devicePixelRatio || 1, 2); W = innerWidth; H = innerHeight; c.width = W * D; c.height = H * D; bars = [];
    for (let n = 0; W / 2 - GAP - n * STEP > -2; n++) { bars.push({ x: W / 2 - GAP - n * STEP, side: -1, n, ph: rnd() * 9, sp: .05 + rnd() * .06, k: Math.floor(rnd() * 4) }); bars.push({ x: W / 2 + GAP + n * STEP, side: 1, n, ph: rnd() * 9, sp: .05 + rnd() * .06, k: Math.floor(rnd() * 4) }); }
  }
  const mixc = (a, b, u) => a.map((v, i) => v + (b[i] - v) * u);
  function step(dt) {
    T += dt;
    if (T >= next) {
      const free = bars.filter((b) => b.n > 0 && !pulses.some((p) => p.bar === b));
      if (free.length) pulses.push({ bar: free[Math.floor(rnd() * free.length)], col: COL[Math.floor(rnd() * 4)], t0: T, tr: trace(), rippled: false });
      next = T + 1.0 + rnd() * .8;
    }
    for (const p of pulses) { if (MODE === 'ripple' && !p.rippled && head(p) < H * .72) { p.rippled = true; ripples.push({ bar: p.bar, col: p.col, t0: T, y: head(p) }); } }
    pulses = pulses.filter((p) => T - p.t0 < RISE + 1.4); ripples = ripples.filter((r) => T - r.t0 < 2.2);
  }
  const head = (p) => H + 20 - (T - p.t0) / RISE * (H + PULSE + 40);
  // The trace a pulse leaves: sharp, like activity on a line chart. Fixed to the bar, so it does not crawl;
  // the pulse's head reveals it and it flattens out behind. Never more than 7px either way.
  const DY = 4;
  function trace() {
    const n = Math.ceil((innerHeight + 300) / DY), a = new Float32Array(n); let burst = 0, sign = 1;
    for (let i = 0; i < n; i++) {
      if (burst <= 0 && rnd() < .11) burst = 2 + Math.floor(rnd() * 6);
      if (burst > 0) { burst--; sign = rnd() < .8 ? -sign : sign; a[i] = sign * (2 + rnd() * rnd() * 5); if (rnd() < .3) a[i] = 0; }
      else a[i] = rnd() < .12 ? (rnd() - .5) * 2 : 0;
    }
    return a;
  }
  function wig(p, y) {
    const d = y - head(p); if (d <= 0) return 0;
    const env = Math.min(1, d / 6) * (d < 170 ? 1 : Math.max(0, 1 - (d - 170) / 230));
    if (env <= 0) return 0;
    return Math.max(-7, Math.min(7, p.tr[Math.max(0, Math.floor((y + 100) / DY))] || 0)) * env;
  }
  function path(b, p, y0, y1) { const bx = b.x + b.side * open; x.beginPath(); if (!p) { x.moveTo(bx, y0); x.lineTo(bx, y1); return; } y0 = Math.floor(y0 / DY) * DY; for (let y = y0; y <= y1 + DY; y += DY) { const X = bx + wig(p, y); if (y === y0) x.moveTo(X, y); else x.lineTo(X, y); } }
  function draw() {
    x.setTransform(D, 0, 0, D, 0, 0); x.clearRect(0, 0, W, H); x.lineCap = 'butt'; x.lineJoin = 'miter';
    const base = x.createLinearGradient(0, 0, 0, H); base.addColorStop(0, 'rgba(160,185,230,.42)'); base.addColorStop(.7, 'rgba(160,185,230,.10)'); base.addColorStop(1, 'rgba(160,185,230,.04)');
    // drift: one soft light wanders behind the bars and changes colour slowly
    const lx = W * (.5 + .46 * Math.sin(T * .13 + .4) * Math.cos(T * .041)), ly = H * (.45 + .3 * Math.sin(T * .09 + 2));
    const ci = (T / 9) % 4, lc = mixc(COL[Math.floor(ci)], COL[(Math.floor(ci) + 1) % 4], ci % 1 < .7 ? 0 : (ci % 1 - .7) / .3);
    for (const b of bars) {
      const p = pulses.find((q) => q.bar === b), bx = b.x + b.side * open;
      if (b.n === 0) { x.shadowColor = 'rgba(232,176,90,.45)'; x.shadowBlur = 14; x.strokeStyle = '#e8b05a'; x.lineWidth = 1.5; path(b, null, 0, H); x.stroke(); x.shadowBlur = 0; continue; }
      x.strokeStyle = base; x.lineWidth = 1.5; path(b, p, 0, H); x.stroke();
      let g = null;
      if (MODE === 'drift') {
        const a = Math.exp(-((bx - lx) ** 2) / (2 * 210 ** 2)) * .95;
        if (a > .02) { g = x.createLinearGradient(0, ly - 330, 0, ly + 330); g.addColorStop(0, `rgba(${lc},0)`); g.addColorStop(.5, `rgba(${lc},${a})`); g.addColorStop(1, `rgba(${lc},0)`); }
      } else if (MODE === 'shimmer') {
        const yy = H * (.5 + .62 * Math.sin(T * b.sp * 2.2 + b.ph)), a = .22 + .68 * Math.max(0, Math.sin(T * b.sp * 1.3 + b.ph * 2.1)) ** 2, cc = COL[b.k];
        g = x.createLinearGradient(0, yy - 200, 0, yy + 200); g.addColorStop(0, `rgba(${cc},0)`); g.addColorStop(.5, `rgba(${cc},${a})`); g.addColorStop(1, `rgba(${cc},0)`);
      }
      if (g) { x.strokeStyle = g; path(b, p, 0, H); x.stroke(); }
      if (MODE === 'ripple') for (const r of ripples) {
        if (r.bar.side !== b.side || r.bar === b) continue;
        const k = Math.abs(b.n - r.bar.n); if (k > 7) continue;
        const u = (T - r.t0 - k * .075) / 1.1; if (u <= 0 || u >= 1) continue;
        const a = Math.sin(u * Math.PI) ** 1.3 * Math.exp(-k * .2), yy = r.y - (T - r.t0) * 120;
        const gg = x.createLinearGradient(0, yy - 240, 0, yy + 240); gg.addColorStop(0, `rgba(${r.col},0)`); gg.addColorStop(.5, `rgba(${r.col},${a})`); gg.addColorStop(1, `rgba(${r.col},0)`);
        x.strokeStyle = gg; path(b, p, 0, H); x.stroke();
      }
    }
    for (const p of pulses) { // the pulse itself, following the bar's wiggle
      const h = head(p); if (h < -PULSE - 10) continue;
      const g = x.createLinearGradient(0, h, 0, h + PULSE); g.addColorStop(0, `rgba(${p.col},0)`); g.addColorStop(.04, 'rgba(255,255,255,.95)'); g.addColorStop(.3, `rgba(${p.col},.95)`); g.addColorStop(1, `rgba(${p.col},0)`);
      x.shadowColor = `rgba(${p.col},.9)`; x.shadowBlur = 9; x.strokeStyle = g; x.lineWidth = 1.8; path(p.bar, p, Math.max(0, h), Math.min(H, h + PULSE)); x.stroke(); x.shadowBlur = 0;
    }
  }
  size(); addEventListener('resize', size);
  if (FROZEN != null || STILL) { if (!STILL) for (let i = 0; i < FROZEN * 60; i++) step(1 / 60); else T = 20; if (document.body.dataset.state === 'in') open = W; draw(); addEventListener('resize', draw); return; }
  let last = performance.now(), t0open = null;
  (function loop(now) {
    const dt = Math.min(.05, (now - last) / 1000); last = now; step(dt);
    if (document.body.dataset.state === 'in') { t0open ??= now; const u = Math.min(1, (now - t0open) / 700); open = (W / 2) * (u < .5 ? 4 * u * u * u : 1 - Math.pow(-2 * u + 2, 3) / 2); } else { t0open = null; open = 0; }
    draw(); requestAnimationFrame(loop);
  })(last);
})();
