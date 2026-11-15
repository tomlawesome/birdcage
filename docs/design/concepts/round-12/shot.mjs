// Dev helper: node shot.mjs <file> <state> <waitMs> <out> [typed]
import { createRequire } from 'node:module';
import { join } from 'node:path';
const require = createRequire(join(process.env.HOME, 'projects/mikroview/frontend/package.json'));
const { chromium } = require('playwright');
const [file, st, wait, out, typed, poke] = process.argv.slice(2);
const b = await chromium.launch({ args: ['--use-gl=swiftshader', '--enable-unsafe-swiftshader', '--ignore-gpu-blocklist'] });
const p = await b.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1 });
p.on('console', (m) => { if (m.type() === 'error') console.log('ERR', m.text()); });
p.on('pageerror', (e) => console.log('PAGEERR', e.message));
await p.goto(`http://127.0.0.1:8317/concepts/round-12/${file}#signin`);
await p.waitForTimeout(500);
if (typed) { await p.focus('#password'); await p.keyboard.type(typed, { delay: 90 }); }
if (st !== 'signin') await p.click(`[data-go="${st}"]`);
await p.waitForTimeout(+wait);
if (poke) { await p.evaluate((o) => BG.poke(JSON.parse(o)), poke); await p.waitForTimeout(300); }
await p.screenshot({ path: out, type: 'jpeg', quality: 88 });
await b.close();
