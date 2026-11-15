// node shot.mjs  -- retakes shots/ from the design host. ?t=N draws the scene as it stands N seconds in.
import { createRequire } from 'node:module';
import { join } from 'node:path';
const require = createRequire(join(process.env.HOME, 'projects/mikroview/frontend/package.json'));
const { chromium } = require('playwright');
const b = await chromium.launch();
for (const [n, st, t] of [['0a-caught', 'signin', 12], ['0b-red', 'signin', 12.75], ['0c-mending', 'signin', 14], ['1-first-run', 'firstrun', 10], ['2-choose', 'choose', 14], ['3-prove', 'prove', 20], ['4-codes', 'codes', 30], ['5-expired', 'expired', 24], ['6-locked', 'locked', 17]]) {
  const p = await b.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
  await p.goto(`http://127.0.0.1:8317/concepts/round-18/direction-an-bars-all-screens.html?t=${t}#${st}`); await p.addStyleTag({ content: '.proto{display:none}' });
  await p.waitForTimeout(900);
  await p.screenshot({ path: `shots/an-${n}.jpg`, type: 'jpeg', quality: 86 }); await p.close();
}
await b.close();
