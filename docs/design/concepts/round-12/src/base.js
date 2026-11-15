const $ = (s) => document.querySelector(s);
const STILL = matchMedia('(prefers-reduced-motion: reduce)').matches;
const ease = (u) => (u < .5 ? 4 * u * u * u : 1 - Math.pow(-2 * u + 2, 3) / 2);
const tweens = new Set();
function tween(o, k, to, ms = 800, delay = 0, fn = ease) {
  for (const t of tweens) if (t.o === o && t.k === k) tweens.delete(t);
  if (STILL || ms <= 0) { o[k] = to; return; }
  tweens.add({ o, k, from: null, to, ms, t0: performance.now() + delay, fn });
}
function stepTweens(now) {
  for (const t of tweens) {
    if (now < t.t0) continue;
    if (t.from === null) t.from = t.o[t.k];
    const u = Math.min(1, (now - t.t0) / t.ms);
    t.o[t.k] = t.from + (t.to - t.from) * t.fn(u);
    if (u >= 1) tweens.delete(t);
  }
}
let state = 'signin';
function go(next, instant) {
  const prev = state; state = next;
  document.body.dataset.state = next;
  $('#err').hidden = next !== 'refused';
  BG.set(next, prev, !!instant);
  const f = next === 'code' ? $('#code') : next === 'in' ? null : $('#password');
  if (f) setTimeout(() => f.focus({ preventScroll: true }), instant ? 0 : 700);
  history.replaceState(null, '', '#' + next);
}
addEventListener('DOMContentLoaded', () => {
  $('#f-signin').addEventListener('submit', (e) => { e.preventDefault(); go($('#password').value ? 'code' : 'refused'); });
  $('#f-code').addEventListener('submit', (e) => { e.preventDefault(); go('in'); });
  document.querySelectorAll('[data-go]').forEach((a) => a.addEventListener('click', (e) => { e.preventDefault(); if (a.dataset.go === 'signin') { $('#password').value = ''; $('#code').value = ''; } go(a.dataset.go); }));
  document.querySelectorAll('input').forEach((i) => i.addEventListener('input', () => BG.key && BG.key(i)));
  BG.init();
  const h = location.hash.slice(1);
  go(['signin', 'refused', 'code', 'in'].includes(h) ? h : 'signin', true);
  const loop = (now) => { stepTweens(now); BG.frame(now / 1000); requestAnimationFrame(loop); };
  requestAnimationFrame(loop);
});
