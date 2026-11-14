// Screenshot every scene of every direction in this round.
// Usage: python3 gen.py && node capture.mjs   (from this directory; borrows mikroview's playwright)
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { readdirSync, mkdirSync } from 'node:fs';

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(join(process.env.HOME, 'projects/mikroview/frontend/package.json'));
const { chromium } = require('playwright');

const files = readdirSync(here).filter((f) => /^direction-.*\.html$/.test(f)).sort();
mkdirSync(join(here, 'shots'), { recursive: true });

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
let n = 0;
for (const f of files) {
  await page.goto('file://' + join(here, f));
  await page.addStyleTag({ content: '.caret { animation: none !important; }' }); // a blinking caret must not be caught hidden
  await page.waitForTimeout(1600); // let entrance motion settle
  const ids = await page.$$eval('section.scene', (els) => els.map((e) => e.id));
  for (const id of ids) {
    const el = await page.$(`#${id}`);
    const out = join(here, 'shots', `${id}.png`);
    await el.screenshot({ path: out });
    n++;
    console.log(out);
  }
}
await browser.close();
console.log(`${n} shots`);
