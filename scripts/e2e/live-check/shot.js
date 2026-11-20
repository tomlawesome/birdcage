// shot.js -- the two screenshots live-check.sh takes: the cage events list
// and the canary's own page. Run inside the Playwright image, on the
// harness's private network, with the host's playwright package mounted.
//
//   node shot.js <dashboard-url> <canary-id> <out-dir>
//
// The dashboard certificate comes from a throwaway CA that exists only for
// this run, so the browser ignores certificate errors; the network has no
// route out, which is what makes that safe. It signs in through the real
// door (password, then an authenticator code) with the throwaway admin
// stack.sh keeps when E2E_KEEP_LOGIN=1, so the pages are drawn as an operator
// would see them.
const fs = require('fs');
const crypto = require('crypto');
const { chromium } = require('playwright');

function totp(secret) {
  const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of secret.toUpperCase().replace(/[= ]/g, '')) bits += alpha.indexOf(c).toString(2).padStart(5, '0');
  const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const h = crypto.createHmac('sha1', key).update(counter).digest();
  const o = h[19] & 15;
  const n = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(n % 1000000).padStart(6, '0');
}

(async () => {
  const [base, canary, out] = process.argv.slice(2);
  const [user, password, secret] = fs.readFileSync('/work/ui-login', 'utf8').trim().split('\n');
  const browser = await chromium.launch();
  const ctx = await browser.newContext({
    viewport: { width: 1280, height: 900 },
    deviceScaleFactor: 1,
    ignoreHTTPSErrors: true,
  });
  const h = { 'X-Requested-With': 'birdcage', 'Content-Type': 'application/json' };
  let r = await ctx.request.post(base + '/api/auth/login', { headers: h, data: { username: user, password } });
  if (!r.ok()) throw new Error('login: ' + r.status());
  r = await ctx.request.post(base + '/api/auth/login/factor', { headers: h, data: { code: totp(secret) } });
  if (!r.ok()) throw new Error('second factor: ' + r.status());
  const page = await ctx.newPage();
  const shots = [
    ['cage-events', base + '/#/'],
    ['canary-page', base + '/#/canaries/' + canary],
  ];
  for (const [name, url] of shots) {
    await page.goto(url, { waitUntil: 'networkidle' });
    await page.waitForTimeout(2500);
    await page.screenshot({ path: out + '/' + name + '.png' });
    console.log(name, 'text:', (await page.innerText('body')).replace(/\s+/g, ' ').slice(0, 400));
  }
  await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
