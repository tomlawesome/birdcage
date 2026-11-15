// Captures the round-12 shots from the design host. Run: node capture.mjs
import { createRequire } from 'node:module';
import { join } from 'node:path';
const require = createRequire(join(process.env.HOME, 'projects/mikroview/frontend/package.json'));
const { chromium } = require('playwright');
const BASE = 'http://127.0.0.1:8317/concepts/round-12/';
const DIRS = [
  ['ab', 'direction-ab-reeded-glass.html', { open: 330 }, 1],
  ['ac', 'direction-ac-ribbons.html', { mix: .82, bg: .4 }, .6],
  ['ad', 'direction-ad-the-dome.html', { cam: 1.55, light: .22 }, 0],
];
const b = await chromium.launch({ args: ['--use-gl=swiftshader', '--enable-unsafe-swiftshader', '--ignore-gpu-blocklist'] });
for (const [id, file, mid, shellMid] of DIRS) {
  const shot = async (name, fn) => {
    const p = await b.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
    p.on('pageerror', (e) => console.log('PAGEERR', id, name, e.message));
    await p.goto(BASE + file + '#signin'); await p.waitForTimeout(600);
    await p.addStyleTag({ content: '.proto{display:none}' });
    await fn(p);
    await p.screenshot({ path: `shots/${id}-${name}.jpg`, type: 'jpeg', quality: 86 });
    await p.close(); console.log(id, name);
  };
  await shot('1-sign-in', async (p) => { await p.focus('#password'); await p.keyboard.type('correct horse', { delay: 80 }); await p.waitForTimeout(500); });
  await shot('2-refused', async (p) => { await p.evaluate(() => go('refused')); await p.waitForTimeout(2600); });
  await shot('3-code', async (p) => { await p.evaluate(() => go('code')); await p.waitForTimeout(3600); });
  await shot('4-entering', async (p) => {
    await p.evaluate(([o, sh]) => { document.body.dataset.state = 'in'; const s = document.querySelector('#shell'); s.style.transition = 'none'; s.style.opacity = sh; BG.poke(o); }, [mid, shellMid]);
    await p.waitForTimeout(700);
  });
  await shot('5-dashboard', async (p) => { await p.evaluate(() => go('in')); await p.waitForTimeout(6500); });
}
await b.close();
