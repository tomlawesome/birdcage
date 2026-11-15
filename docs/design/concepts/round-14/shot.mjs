// node shot.mjs  -- retakes shots/ from the design host. Animations are frozen at a chosen moment.
import { createRequire } from 'node:module';
import { join } from 'node:path';
const require = createRequire(join(process.env.HOME, 'projects/mikroview/frontend/package.json'));
const { chromium } = require('playwright');
const b = await chromium.launch();
const freeze = (g, s) => `.proto{display:none}.bars::before{animation-delay:-${g}s!important;animation-play-state:paused!important}.sig{animation-play-state:paused!important}` + s;
const SIG = { ag: '.sig.lan{animation-delay:-1.2s!important}.sig.srv{animation-delay:-2.1s!important}.sig.iot{animation-delay:-9s!important}.sig.guest{animation-delay:-9s!important}', ah: '.sig.lan{animation-delay:-.35s!important}.sig.srv{animation-delay:-2.2s!important}.sig.iot{animation-delay:-9s!important}.sig.guest{animation-delay:-9s!important}' };
for (const [id, file] of [['ag', 'direction-ag-bars-pulses.html'], ['ah', 'direction-ah-bars-lit.html']]) {
  for (const [n, st, g, typed] of [['1-sign-in', 'signin', 1.6, 1], ['2-glint', 'signin', 3.6, 1], ['3-refused', 'refused', 9], ['4-code', 'code', 4.4], ['5-dashboard', 'in', 9]]) {
    const p = await b.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
    await p.goto(`http://127.0.0.1:8317/concepts/round-14/${file}#${st}`); await p.addStyleTag({ content: freeze(g, SIG[id]) });
    if (typed) await p.fill('#password', 'correct horse');
    await p.waitForTimeout(1800);
    await p.screenshot({ path: `shots/${id}-${n}.jpg`, type: 'jpeg', quality: 86 }); await p.close();
  }
}
await b.close();
