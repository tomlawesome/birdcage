// node shot.mjs  -- retakes shots/ from the design host
import { createRequire } from 'node:module';
import { join } from 'node:path';
const require = createRequire(join(process.env.HOME, 'projects/mikroview/frontend/package.json'));
const { chromium } = require('playwright');
const b = await chromium.launch();
for (const [id, file] of [['ae', 'direction-ae-mikroview-door.html'], ['af', 'direction-af-bars.html']]) {
  for (const [n, st, typed] of [['1-sign-in', 'signin', 1], ['2-refused', 'refused'], ['3-code', 'code'], ['4-dashboard', 'in']]) {
    const p = await b.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
    await p.goto(`http://127.0.0.1:8317/concepts/round-13/${file}#${st}`); await p.addStyleTag({ content: '.proto{display:none}' });
    if (typed) await p.fill('#password', 'correct horse');
    await p.waitForTimeout(2500);
    await p.screenshot({ path: `shots/${id}-${n}.jpg`, type: 'jpeg', quality: 86 }); await p.close();
  }
}
await b.close();
