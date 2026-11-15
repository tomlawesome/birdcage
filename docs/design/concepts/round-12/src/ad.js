// AD · The dome. A wire cage in depth; the view moves from outside, to inside under the dome, then out through the crown.
const BG = (() => {
  let c, x, W, H, D, t0 = 0, tFrozen = null;
  const P = { cam: 0, life: 1, light: 0, pulse: 0 };
  const NB = 40, RH = 1.7, TOP = 2.75, CR = .13;
  const bars = [], rings = [];
  const prof = (s) => { // dome profile, s 0..1 from shoulder to crown: [radius, height]
    const a = s * Math.PI / 2; const r = CR + (1 - CR) * Math.pow(Math.cos(a), .82); return [r, RH + (TOP - RH) * Math.pow(Math.sin(a), .92)];
  };
  function build() {
    for (let i = 0; i < NB; i++) {
      const a = i / NB * Math.PI * 2, pts = [];
      for (let k = 0; k <= 10; k++) pts.push([Math.cos(a), k / 10 * RH, Math.sin(a)]);
      for (let k = 1; k <= 22; k++) { const [r, y] = prof(k / 22); pts.push([r * Math.cos(a), y, r * Math.sin(a)]); }
      bars.push(pts);
    }
    const ring = (r, y, w) => { const pts = []; for (let k = 0; k <= 96; k++) { const a = k / 96 * Math.PI * 2; pts.push([r * Math.cos(a), y, r * Math.sin(a)]); } rings.push({ pts, w }); };
    ring(1, 0, 1.5); ring(1, .06, 1); ring(1, RH, 1.5); ring(1, RH - .06, 1); ring(1, .78, .8);
    let [r, y] = prof(.5); ring(r, y, .8);[r, y] = prof(1); ring(r, y, 1.6); ring(r * .55, y + .05, 1);
  }
  const KEYS = [
    { p: [-1.02, 1.0, 4.3], t: [-1.02, 1.42, 0], f: 1.55, foc: 4.3 },
    { p: [.34, .30, .52], t: [-.62, 2.1, -.30], f: .80, foc: 2.4 },
    { p: [0, 3.5, .02], t: [0, 6, 0], f: .8, foc: 2 },
  ];
  const lerp = (a, b, u) => a + (b - a) * u, l3 = (a, b, u) => [lerp(a[0], b[0], u), lerp(a[1], b[1], u), lerp(a[2], b[2], u)];
  function camAt(cv) { const i = Math.min(1, Math.floor(cv)), u = Math.min(1, cv - i), A = KEYS[i], B = KEYS[i + 1]; return { p: l3(A.p, B.p, u), t: l3(A.t, B.t, u), f: lerp(A.f, B.f, u), foc: lerp(A.foc, B.foc, u) }; }
  const sub = (a, b) => [a[0] - b[0], a[1] - b[1], a[2] - b[2]], dot = (a, b) => a[0] * b[0] + a[1] * b[1] + a[2] * b[2];
  const cross = (a, b) => [a[1] * b[2] - a[2] * b[1], a[2] * b[0] - a[0] * b[2], a[0] * b[1] - a[1] * b[0]];
  const norm = (a) => { const l = Math.hypot(...a) || 1; return [a[0] / l, a[1] / l, a[2] / l]; };
  function size() { D = Math.min(devicePixelRatio || 1, 2); W = innerWidth; H = innerHeight; c.width = W * D; c.height = H * D; }
  const CAN = [[57, 135, 229], [25, 158, 112], [201, 133, 0], [215, 106, 158]];
  return {
    init() { c = $('#bg'); x = c.getContext('2d'); build(); size(); addEventListener('resize', size); },
    set(next, prev, instant) {
      const ms = (m) => (instant ? 0 : m);
      $('#shell').style.transition = instant ? 'none' : 'opacity 1300ms ease 1500ms';
      $('#shell').style.opacity = next === 'in' ? 1 : 0;
      c.style.transitionDelay = next === 'in' && !instant ? '1700ms' : '0ms'; c.style.transitionDuration = instant ? '0ms' : '';
      c.style.opacity = next === 'in' ? 0 : 1;
      if (next === 'signin') { tween(P, 'cam', 0, ms(1800)); tween(P, 'life', 1, ms(800)); tween(P, 'light', 0, ms(400)); }
      if (next === 'refused') { tween(P, 'cam', 0, ms(1200)); tween(P, 'life', .12, ms(450)); tween(P, 'light', 0, 0); }
      if (next === 'code') { tween(P, 'cam', 1, ms(2400)); tween(P, 'life', 1, ms(700)); tween(P, 'light', 0, ms(400)); }
      if (next === 'in') { tween(P, 'cam', 2, ms(2400)); tween(P, 'life', 1, ms(300)); tween(P, 'light', 1, ms(1500), instant ? 0 : 700); }
    },
    key() { if (state === 'refused') tween(P, 'life', 1, 600); P.pulse = 1; tween(P, 'pulse', 0, 900); },
    poke(o) { tweens.clear(); if (o.t != null) tFrozen = o.t; Object.assign(P, o); },
    frame(t) {
      if (!t0) t0 = t;
      const T = tFrozen != null ? tFrozen : STILL ? 8 : t - t0 + 8;
      const w = c.width, h = c.height, cam = camAt(P.cam), life = P.life;
      const fw = norm(sub(cam.t, cam.p)), rt = norm(cross(fw, [0, 1, 0])), up = cross(rt, fw), F = cam.f * h;
      const rot = T * .035, cr = Math.cos(rot), sr = Math.sin(rot);
      const proj = (q, spin = true) => {
        const X = spin ? q[0] * cr - q[2] * sr : q[0], Z = spin ? q[0] * sr + q[2] * cr : q[2];
        const d = [X - cam.p[0], q[1] - cam.p[1], Z - cam.p[2]], z = dot(d, fw);
        return [w / 2 + dot(d, rt) / z * F, h / 2 - dot(d, up) / z * F, z];
      };
      x.globalCompositeOperation = 'source-over';
      const g0 = x.createLinearGradient(0, 0, 0, h); g0.addColorStop(0, '#05070c'); g0.addColorStop(.55, '#080b14'); g0.addColorStop(1, '#04050a');
      x.fillStyle = g0; x.fillRect(0, 0, w, h);
      x.globalCompositeOperation = 'lighter'; x.lineCap = 'round';
      const blob = (q, rad, col, a, spin) => {
        const s = proj(q, spin); if (s[2] < .08) return; const R = rad * F / s[2];
        const g = x.createRadialGradient(s[0], s[1], 0, s[0], s[1], R);
        g.addColorStop(0, `rgba(${col},${a})`); g.addColorStop(.25, `rgba(${col},${a * .42})`); g.addColorStop(1, `rgba(${col},0)`);
        x.fillStyle = g; x.fillRect(s[0] - R, s[1] - R, R * 2, R * 2);
      };
      // light under the crown, and a pool on the floor
      const warm = `${Math.round(lerp(150, 255, life))},${Math.round(lerp(165, 206, life))},${Math.round(lerp(200, 138, life))}`;
      blob([0, TOP - .25, 0], 1.5, warm, (.34 + P.pulse * .2) * lerp(.3, 1, life), false);
      blob([0, 1.0, 0], 1.25, '60,90,160', .16 * lerp(.4, 1, life), false);
      const cans = CAN.map((col, i) => { const a = i / 4 * Math.PI * 2 + .6 + T * .05; return [.46 * Math.cos(a), .92 + .035 * Math.sin(T * .9 + i * 1.7), .46 * Math.sin(a)]; });
      const lit = (q) => { // how much the inside lights reach this point of a bar
        const dy = q[1] - (TOP - .3), d2 = q[0] * q[0] + dy * dy + q[2] * q[2]; let v = .9 / (1 + d2 * 1.5);
        for (const k of cans) { const e = (q[0] - k[0]) ** 2 + (q[1] - k[1]) ** 2 + (q[2] - k[2]) ** 2; v += .16 / (.12 + e * 2.2); }
        return v;
      };
      const run = (pts, wt, st, spin) => {
        for (let i = 0; i < pts.length - 1; i += st) {
          const j = Math.min(pts.length - 1, i + st), m = pts[(i + j) >> 1], pm = proj(m, spin);
          if (pm[2] < .12) continue;
          const z = pm[2], base = wt * .0085 * F / z, coc = Math.abs(1 / z - 1 / cam.foc) * F * .014;
          const nearK = Math.max(0, Math.min(1, (cam.foc + .95 - z) / 1.9));
          const L = Math.min(1.6, .27 + lit(m) * (.5 + P.pulse * .3)) * lerp(.45, 1, life);
          const wr = lerp(150, lerp(128, 236, nearK), life), wg = lerp(160, lerp(150, 178, nearK), life), wb = lerp(190, lerp(205, 96, nearK), life);
          const sharp = base / (base + coc), al = (.3 + .7 * nearK) * L;
          x.beginPath(); let ok = true;
          for (let k = i; k <= j; k++) { const s = proj(pts[k], spin); if (s[2] < .07) { ok = false; break; } if (k === i) x.moveTo(s[0], s[1]); else x.lineTo(s[0], s[1]); }
          if (!ok) continue;
          x.strokeStyle = `rgba(${wr | 0},${wg | 0},${wb | 0},${Math.min(1, .22 * al * sharp + .07 * al).toFixed(3)})`; x.lineWidth = base * 2.8 + coc * 2.2 + D; x.stroke();
          if (sharp > .2) { x.strokeStyle = `rgba(${Math.min(255, wr + 14) | 0},${Math.min(255, wg + 22) | 0},${Math.min(255, wb + 40) | 0},${Math.min(1, al * sharp * .85).toFixed(3)})`; x.lineWidth = Math.max(D * .7, base * .75); x.stroke(); }
        }
      };
      x.lineCap = 'butt'; x.lineJoin = 'round';
      for (const pts of bars) run(pts, 1, 2, true);
      for (const r of rings) run(r.pts, r.w, 3, true);
      // four lights on the perch ring: the canary colours
      CAN.forEach((col, i) => {
        const q = cans[i];
        const cc = col.map((v) => Math.round(lerp((col[0] + col[1] + col[2]) / 3 * .8 + 30, v, life))).join(',');
        blob(q, .34, cc, .5 * lerp(.35, 1, life) + P.pulse * .25, false);
        blob(q, .034, '255,255,255', .9 * lerp(.3, 1, life), false);
      });
      if (P.light > 0) { x.fillStyle = `rgba(255,236,204,${P.light})`; const s = proj([0, TOP, 0], false); const R = Math.hypot(w, h) * (.05 + P.light * 1.3); const g = x.createRadialGradient(s[0], s[1], 0, s[0], s[1], R); g.addColorStop(0, `rgba(255,240,214,${Math.min(1, P.light * 1.6)})`); g.addColorStop(1, 'rgba(255,220,170,0)'); x.fillStyle = g; x.fillRect(0, 0, w, h); }
      x.globalCompositeOperation = 'source-over';
      const v = x.createRadialGradient(w / 2, h / 2, h * .35, w / 2, h / 2, h * 1.05); v.addColorStop(0, 'rgba(3,4,8,0)'); v.addColorStop(1, `rgba(3,4,8,${.62 * (1 - P.light)})`);
      x.fillStyle = v; x.fillRect(0, 0, w, h);
      const sc = x.createLinearGradient(0, 0, w * .5, 0); sc.addColorStop(0, `rgba(5,7,12,${(.72 + .2 * Math.min(1, P.cam)) * (1 - P.light)})`); sc.addColorStop(.6, `rgba(5,7,12,${(.3 + .35 * Math.min(1, P.cam)) * (1 - P.light)})`); sc.addColorStop(1, 'rgba(5,7,12,0)'); x.fillStyle = sc; x.fillRect(0, 0, w * .5, h);
    },
  };
})();
