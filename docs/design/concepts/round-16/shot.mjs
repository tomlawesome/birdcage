// node shot.mjs  -- retakes shots/ from the design host. ?t=N draws the scene as it stands N seconds in.
import { createRequire } from 'node:module';
import { join } from 'node:path';
const require = createRequire(join(process.env.HOME, 'projects/mikroview/frontend/package.json'));
const { chromium } = require('playwright');
const b = await chromium.launch();
for (const [id, file] of [['al', 'direction-al-bars-trace.html']]) {
  for (const [n, st, t, typed] of [['1-sign-in', 'signin', 10, 1], ['2-later', 'signin', 20, 1], ['3-refused', 'refused', 14], ['4-code', 'code', 30]]) {
    const p = await b.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
    await p.goto(`http://127.0.0.1:8317/concepts/round-16/${file}?t=${t}#${st}`); await p.addStyleTag({ content: '.proto{display:none}' });
    if (typed) await p.fill('#password', 'correct horse');
    await p.waitForTimeout(900);
    await p.screenshot({ path: `shots/${id}-${n}.jpg`, type: 'jpeg', quality: 86 }); await p.close();
  }
}
await b.close();
