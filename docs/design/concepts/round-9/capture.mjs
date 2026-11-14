// Screenshot every scene of every direction in this round, plus two frames of each motion page.
// Usage: python3 gen.py && node capture.mjs   (from this directory; borrows mikroview's playwright)
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { readdirSync, mkdirSync } from 'node:fs';

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(join(process.env.HOME, 'projects/mikroview/frontend/package.json'));
const { chromium } = require('playwright');
const only = process.argv[2]; // optional: a letter, to recapture one direction

const files = readdirSync(here).filter((f) => /^direction-.*\.html$/.test(f) && (!only || f.startsWith(`direction-${only}`))).sort();
const motions = readdirSync(here).filter((f) => /^motion-.*\.html$/.test(f) && (!only || f === `motion-${only}.html`)).sort();
mkdirSync(join(here, 'shots'), { recursive: true });

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
let n = 0;
for (const f of files) {
  await page.goto('file://' + join(here, f));
  await page.addStyleTag({ content: '.caret { animation: none !important; }' }); // a blinking caret must not be caught hidden
  await page.waitForTimeout(1800); // let entrance motion settle
  const ids = await page.$$eval('section.scene', (els) => els.map((e) => e.id));
  for (const id of ids) {
    const el = await page.$(`#${id}`);
    const out = join(here, 'shots', `${id}.jpg`);
    await el.screenshot({ path: out, type: 'jpeg', quality: 90 });
    n++;
    console.log(out);
  }
}
// motion pages: one frame as door two lands (~4.9 s into the 12 s loop) and one as the cage fills (~10.2 s)
for (const f of motions) {
  const letter = f.match(/motion-(\w)/)[1];
  await page.goto('file://' + join(here, f));
  await page.addStyleTag({ content: '.caret { animation: none !important; }' });
  const t0 = Date.now();
  for (const [name, at] of [['motion', 4900], ['motion-cage', 10200]]) {
    const wait = at - (Date.now() - t0);
    if (wait > 0) await page.waitForTimeout(wait);
    const out = join(here, 'shots', `${letter}-${name}.jpg`);
    await (await page.$('.stage')).screenshot({ path: out, type: 'jpeg', quality: 90 });
    n++;
    console.log(out);
  }
  // the reduced-motion still
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.reload();
  await page.waitForTimeout(400);
  const out = join(here, 'shots', `${letter}-motion-still.jpg`);
  await (await page.$('.stage')).screenshot({ path: out, type: 'jpeg', quality: 90 });
  await page.emulateMedia({ reducedMotion: 'no-preference' });
  n++;
  console.log(out);
}
await browser.close();
console.log(`${n} shots`);
