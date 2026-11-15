const $ = (s) => document.querySelector(s);
function go(next) {
  document.body.dataset.state = next;
  $('#err').hidden = next !== 'refused';
  document.querySelectorAll('.proto a').forEach((a) => a.classList.toggle('on', a.dataset.go === next));
  const f = next === 'code' ? $('#code') : next === 'in' ? null : $('#password');
  if (f) f.focus({ preventScroll: true });
  history.replaceState(null, '', '#' + next);
}
addEventListener('DOMContentLoaded', () => {
  $('#f-signin').addEventListener('submit', (e) => { e.preventDefault(); go($('#password').value ? 'code' : 'refused'); });
  $('#f-code').addEventListener('submit', (e) => { e.preventDefault(); go('in'); });
  document.querySelectorAll('[data-go]').forEach((a) => a.addEventListener('click', (e) => { e.preventDefault(); if (a.dataset.go === 'signin') { $('#password').value = ''; $('#code').value = ''; } go(a.dataset.go); }));
  const h = location.hash.slice(1);
  go(['signin', 'refused', 'code', 'in'].includes(h) ? h : 'signin');
});
