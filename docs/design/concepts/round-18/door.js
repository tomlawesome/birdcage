const $ = (s) => document.querySelector(s);
const STATES = ['signin', 'refused', 'code', 'locked', 'firstrun', 'choose', 'prove', 'codes', 'expired', 'in'];
const FOCUS = { signin: '#password', refused: '#password', code: '#code', firstrun: '#setup', prove: '#prove-code', expired: '#again' };
function go(next) {
  document.body.dataset.state = next;
  $('#err').hidden = next !== 'refused'; $('#lock').hidden = next !== 'locked';
  document.querySelectorAll('.proto a').forEach((a) => a.classList.toggle('on', a.dataset.go === next));
  const f = FOCUS[next] && $(FOCUS[next]); if (f) f.focus({ preventScroll: true });
  history.replaceState(null, '', '#' + next);
}
function qr() { // a placeholder pattern, not a real key
  const c = $('#qr'), x = c.getContext('2d'), N = 29, s = c.width / N; let seed = 7;
  const r = () => (seed = (seed * 16807) % 2147483647) / 2147483647;
  x.fillStyle = '#fff'; x.fillRect(0, 0, c.width, c.width); x.fillStyle = '#06080e';
  const eye = (i, j) => i < 8 && j < 8 || i >= N - 8 && j < 8 || i < 8 && j >= N - 8;
  for (let i = 0; i < N; i++) for (let j = 0; j < N; j++) if (!eye(i, j) && r() < .48) x.fillRect(i * s, j * s, s + .5, s + .5);
  for (const [a, b] of [[0, 0], [N - 7, 0], [0, N - 7]]) { x.fillRect(a * s, b * s, 7 * s, 7 * s); x.fillStyle = '#fff'; x.fillRect((a + 1) * s, (b + 1) * s, 5 * s, 5 * s); x.fillStyle = '#06080e'; x.fillRect((a + 2) * s, (b + 2) * s, 3 * s, 3 * s); }
}
addEventListener('DOMContentLoaded', () => {
  qr();
  const on = (id, fn) => $(id).addEventListener('submit', (e) => { e.preventDefault(); fn(); });
  on('#f-signin', () => go($('#password').value ? 'code' : 'refused'));
  on('#f-code', () => go('in')); on('#f-firstrun', () => go('choose')); on('#f-prove', () => go('codes')); on('#f-codes', () => go('in')); on('#f-expired', () => go('in')); on('#f-choose', () => go('prove'));
  document.querySelectorAll('[data-go]').forEach((a) => a.addEventListener('click', (e) => { e.preventDefault(); go(a.dataset.go); }));
  const h = location.hash.slice(1);
  go(STATES.includes(h) ? h : 'signin');
});
