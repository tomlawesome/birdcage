// The bars: drawn on a canvas so a bar can move. Pulses climb random bars and leave a sharp, unruly trace that reaches the bars around them;
// data-glint on <body> picks how the rest of the bars catch light: drift | ripple | shimmer.
(() => {
  const c = document.querySelector('#bars'), x = c.getContext('2d');
  const MODE = document.body.dataset.glint, STILL = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const q = new URLSearchParams(location.search), FROZEN = q.has('t') ? +q.get('t') : null;
  let seed = 20261115; const rnd = () => { seed |= 0; seed = seed + 0x6D2B79F5 | 0; let t = Math.imul(seed ^ seed >>> 15, 1 | seed); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; };
  const COL = [[57, 135, 229], [25, 158, 112], [232, 176, 90], [215, 106, 158]], RED = [236, 72, 80];
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
      if (free.length) pulses.push(newPulse(free[Math.floor(rnd() * free.length)]));
      next = T + .35 + rnd() * rnd() * 2.6;
    }
    for (const p of pulses) { if (MODE === 'ripple' && !p.rippled && head(p) < H * .72) { p.rippled = true; ripples.push({ bar: p.bar, col: p.col, t0: T, y: head(p) }); } }
    pulses = pulses.filter((p) => p.stop != null ? T - p.tc < HOLD : T - p.t0 < RISE + 2.2); ripples = ripples.filter((r) => T - r.t0 < 2.2);
  }
  // About one pulse in four is caught: it stops dead part-way up, the bar is cut there and pulses red, then mends.
  const head = (p) => { const h = H + 20 - (T - p.t0) / RISE * (H + PULSE + 40); return p.stop != null ? Math.max(h, p.stop) : h; };
  const ca = (p) => p.stop == null ? -1 : T - p.tc; // seconds since it was caught
  const live = (p) => { const a = ca(p); return a <= 0 ? 1 : Math.max(0, 1 - a / .4); };
  const HOLD = 2.7;
  // The trace a pulse leaves: sharp, like activity on a line chart, and unruly. Spikes are mostly small with a few
  // long ones that reach across the neighbouring bars; the trace flickers while it lasts. The two bars either side
  // pick up a weaker trace of their own, so a pulse disturbs its neighbourhood, not one line.
  const DY = 3, REACH = 62, NEAR = [1, .34, .13], LAG = 26;
  const hsh = (i, j) => { const v = Math.sin(i * 127.1 + j * 311.7) * 43758.5453; return v - Math.floor(v); };
  function trace(big) {
    const n = Math.ceil((innerHeight + 400) / DY), a = new Float32Array(n); let burst = 0, sign = 1, hold = 0;
    for (let i = 0; i < n; i++) {
      if (burst <= 0 && rnd() < .07) burst = 3 + Math.floor(rnd() * rnd() * 26);
      if (burst > 0) {
        burst--; if (hold > 0) { hold--; a[i] = a[i - 1] || 0; continue; }
        sign = rnd() < .72 ? -sign : sign; a[i] = sign * (3 + Math.pow(rnd(), 3.2) * big); if (rnd() < .22) a[i] = 0; if (rnd() < .18) hold = 1 + Math.floor(rnd() * 3);
      } else a[i] = rnd() < .1 ? (rnd() - .5) * 5 : 0;
    }
    return a;
  }
  const newPulse = (bar) => { const p = { bar, col: COL[Math.floor(rnd() * 4)], t0: T, id: Math.floor(rnd() * 1e4), tr: [trace(REACH), trace(REACH), trace(REACH)], rippled: false }; if (rnd() < .27) { p.stop = H * (.2 + rnd() * .5); p.tc = T + (H + 20 - p.stop) / (H + PULSE + 40) * RISE; } return p; };
  function part(p, k, y) { // what pulse p does at height y to a bar k places away from its own
    const d = y - head(p) - k * LAG; if (d <= 0) return 0;
    const env = Math.min(1, d / 5) * (d < 240 ? 1 : Math.max(0, 1 - (d - 240) / 320)); if (env <= 0) return 0;
    const i = Math.max(0, Math.floor((y + 120) / DY)), v = p.tr[k][i] || 0; if (!v) return 0;
    return v * NEAR[k] * env * live(p) * (.45 + 1.0 * hsh(i + p.id + k * 97, Math.floor(T * 13)));
  }
  const near = (b) => b.n === 0 ? [] : pulses.filter((p) => p.bar.side === b.side && Math.abs(p.bar.n - b.n) <= 2);
  function off(b, ps, y) {
    let v = 0; for (const p of ps) v += part(p, Math.abs(p.bar.n - b.n), y);
    v = Math.max(-REACH, Math.min(REACH, v));
    if (b.n === 1 && v * b.side < 0) v = Math.max(-36, Math.min(36, v)); // never across the amber posts into the form
    return v;
  }
  function path(b, ps, y0, y1) { const bx = b.x + b.side * open; x.beginPath(); if (!ps || !ps.length) { x.moveTo(bx, y0); x.lineTo(bx, y1); return; } y0 = Math.floor(y0 / DY) * DY; for (let y = y0; y <= y1 + DY; y += DY) { const X = bx + off(b, ps, y); if (y === y0) x.moveTo(X, y); else x.lineTo(X, y); } }
  function draw() {
    x.setTransform(D, 0, 0, D, 0, 0); x.clearRect(0, 0, W, H); x.lineCap = 'butt'; x.lineJoin = 'miter';
    const base = x.createLinearGradient(0, 0, 0, H); base.addColorStop(0, 'rgba(160,185,230,.42)'); base.addColorStop(.7, 'rgba(160,185,230,.10)'); base.addColorStop(1, 'rgba(160,185,230,.04)');
    // drift: one soft light wanders behind the bars and changes colour slowly
    const lx = W * (.5 + .46 * Math.sin(T * .13 + .4) * Math.cos(T * .041)), ly = H * (.45 + .3 * Math.sin(T * .09 + 2));
    const ci = (T / 9) % 4, lc = mixc(COL[Math.floor(ci)], COL[(Math.floor(ci) + 1) % 4], ci % 1 < .7 ? 0 : (ci % 1 - .7) / .3);
    for (const b of bars) {
      const p = near(b), bx = b.x + b.side * open;
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
    for (const p of pulses) { // the disturbed stretch takes the pulse's colour, on its own bar and fainter on the neighbours
      const h = head(p); if (h > H) continue;
      for (const b of bars) {
        if (b.side !== p.bar.side || b.n === 0) continue; const k = Math.abs(b.n - p.bar.n); if (k > 2) continue;
        const y0 = Math.max(0, h + k * LAG), y1 = Math.min(H, y0 + 560); if (y1 <= y0) continue;
        const g = x.createLinearGradient(0, h + k * LAG, 0, h + k * LAG + 560), a = [.85, .5, .28][k] * live(p); g.addColorStop(0, `rgba(${p.col},${a})`); g.addColorStop(.45, `rgba(${p.col},${a * .7})`); g.addColorStop(1, `rgba(${p.col},0)`);
        x.strokeStyle = g; x.lineWidth = k ? 1.2 : 1.5; path(b, near(b), y0, y1); x.stroke();
      }
    }
    for (const p of pulses) { // the pulse itself, following the bar
      const h = head(p), f = live(p); if (h < -PULSE - 10 || f <= 0) continue; const col = ca(p) > 0 ? RED : p.col;
      const g = x.createLinearGradient(0, h, 0, h + PULSE); g.addColorStop(0, `rgba(${col},0)`); g.addColorStop(.04, `rgba(255,255,255,${.95 * f})`); g.addColorStop(.3, `rgba(${col},${.95 * f})`); g.addColorStop(1, `rgba(${col},0)`);
      x.shadowColor = `rgba(${col},.9)`; x.shadowBlur = 9; x.strokeStyle = g; x.lineWidth = 1.8; path(p.bar, near(p.bar), Math.max(0, h), Math.min(H, h + PULSE)); x.stroke(); x.shadowBlur = 0;
    }
    for (const p of pulses) { // caught: the cut, the red beat, the mend
      const a = ca(p); if (a <= 0) continue;
      const bx = p.bar.x + p.bar.side * open, y = p.stop;
      const beat = Math.exp(-a * 1.25) * (.5 + .5 * Math.cos(a * 15)) + .22 * Math.max(0, 1 - a / HOLD), A = Math.min(1, beat) * Math.min(1, (HOLD - a) / .5);
      const gap = 8 * (a < .1 ? a / .1 : a < 1.7 ? 1 : Math.max(0, 1 - (a - 1.7) / .8));
      const g = x.createLinearGradient(0, y - 190, 0, y + 190); g.addColorStop(0, `rgba(${RED},0)`); g.addColorStop(.5, `rgba(${RED},${A})`); g.addColorStop(1, `rgba(${RED},0)`);
      x.shadowColor = `rgba(${RED},${A})`; x.shadowBlur = 12; x.strokeStyle = g; x.lineWidth = 1.8; x.beginPath(); x.moveTo(bx, y - 190); x.lineTo(bx, y + 190); x.stroke(); x.shadowBlur = 0;
      if (gap > .3) {
        x.clearRect(bx - 5, y - gap, 10, gap * 2);
        x.strokeStyle = `rgba(${RED},${Math.min(1, .35 + A)})`; x.lineWidth = 1.5; x.beginPath(); x.moveTo(bx - 5, y - gap); x.lineTo(bx + 5, y - gap); x.moveTo(bx - 5, y + gap); x.lineTo(bx + 5, y + gap); x.stroke();
      }
    }
  }
  size(); addEventListener('resize', size);
  if (FROZEN != null || STILL) { if (!STILL) for (let i = 0; i < FROZEN * 60; i++) step(1 / 60); else T = 20; if (document.body.dataset.state === 'in') open = W; document.body.dataset.caught = pulses.filter((p) => p.stop != null).map((p) => (T - p.tc).toFixed(2)).join(' '); draw(); addEventListener('resize', draw); return; }
  let last = performance.now(), t0open = null;
  (function loop(now) {
    const dt = Math.min(.05, (now - last) / 1000); last = now; step(dt);
    if (document.body.dataset.state === 'in') { t0open ??= now; const u = Math.min(1, (now - t0open) / 700); open = (W / 2) * (u < .5 ? 4 * u * u * u : 1 - Math.pow(-2 * u + 2, 3) / 2); } else { t0open = null; open = 0; }
    draw(); requestAnimationFrame(loop);
  })(last);
})();
