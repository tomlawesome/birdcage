// Screenshot every scene of every direction in this round.
// Usage: node capture.mjs   (from this directory; borrows mikroview's playwright)
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { readdirSync, mkdirSync } from 'node:fs';

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(join(process.env.HOME, 'projects/mikroview/frontend/package.json'));
const { chromium } = require('playwright');

const files = readdirSync(here).filter((f) => /^direction-.*\.html$/.test(f));
mkdirSync(join(here, 'shots'), { recursive: true });

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1600, height: 1000 }, deviceScaleFactor: 2 });
for (const f of files) {
  await page.goto('file://' + join(here, f));
  const ids = await page.$$eval('section.scene', (els) => els.map((e) => e.id));
  for (const id of ids) {
    const el = await page.$(`#${id}`);
    const out = join(here, 'shots', `${id}.png`);
    await el.screenshot({ path: out });
    console.log(out);
  }
}
await browser.close();
