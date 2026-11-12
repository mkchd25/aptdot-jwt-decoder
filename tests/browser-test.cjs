// Real-browser test (Chromium via Playwright).
// Real-browser checks. Usage: npm run test:browser   (or node tests/browser-test.cjs [repo root] [screenshot dir])
const { chromium } = require('playwright');
const path = require('path');
const fs = require('fs');

const root = process.argv[2] || path.join(__dirname, '..');
const shots = process.argv[3] || fs.mkdtempSync(path.join(require('os').tmpdir(), 'jwt-shots-'));
const css = fs.readFileSync(path.join(root, 'src/jwt-decoder.css'), 'utf8');
const js = fs.readFileSync(path.join(root, 'src/jwt-decoder.js'), 'utf8');
const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>JWT Decoder test</title>
<style>body{background:#0d1117;color:#c9d1d9;font-family:system-ui,sans-serif;margin:0;padding:16px;max-width:1100px}</style><style>${css}</style></head>
<body><h1>JWT Decoder &amp; Verifier</h1><div class="aptdot-jwt-app google-anno-skip"><p class="jwt-loading">Loading</p></div><script>${js}</script></body></html>`;

let pass = 0, fail = 0;
const failures = [];
const ok = (c, n) => { if (c) pass++; else { fail++; failures.push(n); } };

(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const page = await ctx.newPage();
  const errors = [];
  const requests = [];
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
  page.on('pageerror', (e) => errors.push(e.message));
  page.on('request', (r) => requests.push(r.url()));
  await page.route('https://www.aptdot.com/tools/jwt-decoder/', (r) => r.fulfill({ status: 200, contentType: 'text/html', body: html }));
  await page.goto('https://www.aptdot.com/tools/jwt-decoder/');
  await page.waitForSelector('.jwt-tabs');
  ok(await page.locator('.jwt-loading').count() === 0, 'Loading text replaced by the app');

  const samples = ['access', 'idtoken', 'es256', 'ed25519', 'expired', 'none', 'risky'];
  for (const s of samples) {
    await page.selectOption('.jwt-toolbar select', s);
    await page.waitForFunction(() => document.querySelector('.jwt-verify') && document.querySelector('.jwt-verify').textContent.length > 5, null, { timeout: 15000 });
    await page.waitForTimeout(250);
    const v = await page.locator('.jwt-verify').innerText();
    const st = await page.locator('.jwt-status').innerText();
    if (s === 'none') ok(/Invalid signature/.test(v) && /Unsigned/.test(st), `Browser sample ${s}: ${st} | ${v.slice(0, 60)}`);
    else ok(/Signature verified/.test(v), `Browser sample ${s}: ${v.slice(0, 80)}`);
    if (s === 'expired') ok(/Expired/.test(st), 'Expired sample shows Expired in status');
    if (s === 'idtoken') {
      await page.screenshot({ path: path.join(shots, 'desktop-idtoken.png'), fullPage: true });
      const rows = await page.locator('.jwt-table tbody tr').count();
      ok(rows >= 14, `ID token claims table has ${rows} rows`);
    }
    if (s === 'risky') await page.screenshot({ path: path.join(shots, 'desktop-risky.png'), fullPage: true });
  }

  // Tamper a character in the payload: signature must fail
  await page.selectOption('.jwt-toolbar select', 'access');
  await page.waitForTimeout(600);
  const tok = await page.locator('textarea').first().inputValue();
  const parts = tok.split('.');
  const p = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
  p.roles = ['admin'];
  await page.locator('textarea').first().fill(parts[0] + '.' + Buffer.from(JSON.stringify(p)).toString('base64url') + '.' + parts[2]);
  await page.waitForTimeout(700);
  ok(/Invalid signature/.test(await page.locator('.jwt-verify').innerText()), 'Edited payload shows Invalid signature');

  // Fetch keys via issuer discovery (simulated issuer with CORS)
  await page.selectOption('.jwt-toolbar select', 'es256');
  await page.waitForTimeout(800);
  const jwks = await page.locator('.jwt-key textarea').inputValue();
  const keyReqs = [];
  await page.route('https://auth.example.com/.well-known/openid-configuration', (r) => { keyReqs.push(r.request()); r.fulfill({ status: 200, contentType: 'application/json', headers: { 'access-control-allow-origin': '*' }, body: JSON.stringify({ issuer: 'https://auth.example.com/', jwks_uri: 'https://auth.example.com/jwks.json' }) }); });
  await page.route('https://auth.example.com/jwks.json', (r) => { keyReqs.push(r.request()); r.fulfill({ status: 200, contentType: 'application/json', headers: { 'access-control-allow-origin': '*' }, body: jwks }); });
  await page.locator('.jwt-key textarea').fill('');
  await page.waitForTimeout(400);
  await page.getByRole('button', { name: 'Fetch keys', exact: true }).click();
  await page.waitForFunction(() => /Signature verified/.test(document.querySelector('.jwt-verify').textContent), null, { timeout: 10000 });
  ok(true, 'Fetch keys via issuer discovery then verifies');
  const tokNow = await page.locator('textarea').first().inputValue();
  ok(keyReqs.length === 2 && keyReqs.every((r) => !r.url().includes(tokNow.slice(10, 40)) && !(r.headers()['authorization']) && !(r.headers()['cookie'])), 'Key fetch sends no token, cookies or Authorization header');
  ok(keyReqs.every((r) => !r.headers()['referer']), 'Key fetch sends no Referer');

  // CORS failure gives a helpful message
  await page.route('https://nocors.example.com/**', (r) => r.abort('failed')); // what the page sees when CORS blocks a response
  await page.locator('input[type=url]').fill('https://nocors.example.com/jwks.json');
  await page.getByRole('button', { name: 'Fetch keys', exact: true }).click();
  await page.waitForTimeout(1500);
  ok(/CORS/.test(await page.locator('.jwt-verify').innerText()), 'CORS failure explained');
  await page.locator('input[type=url]').fill('http://insecure.example.com/jwks.json');
  await page.getByRole('button', { name: 'Fetch keys', exact: true }).click();
  await page.waitForTimeout(500);
  ok(/Only https/.test(await page.locator('.jwt-verify').innerText()), 'http:// key URLs refused');

  // Encoder: ES384 key pair -> token -> verified in decoder
  await page.click('role=tab[name="Create a test token"]');
  await page.selectOption('.jwt-pane:not([hidden]) select', 'ES384');
  await page.getByRole('button', { name: 'Generate a key pair', exact: true }).click();
  await page.waitForSelector('text=Key pair generated');
  await page.getByRole('button', { name: 'Create token', exact: true }).click();
  await page.waitForTimeout(1200);
  await page.click('role=tab[name="Decode & verify"]');
  ok(/Signature verified/.test(await page.locator('.jwt-verify').innerText()) && /ES384/.test(await page.locator('.jwt-status').innerText()), 'Encoder ES384 token verifies in the decoder');
  await page.click('role=tab[name="Create a test token"]');
  await page.selectOption('.jwt-pane:not([hidden]) select', 'HS512');
  await page.getByRole('button', { name: 'Random secret', exact: true }).click();
  await page.getByRole('button', { name: 'Create token', exact: true }).click();
  await page.waitForTimeout(800);
  await page.click('role=tab[name="Decode & verify"]');
  ok(/Signature verified/.test(await page.locator('.jwt-verify').innerText()), 'Encoder HS512 token verifies in the decoder');

  // Keyboard: arrow keys switch tabs, focus visible
  await page.focus('role=tab[name="Decode & verify"]');
  await page.keyboard.press('ArrowRight');
  ok(await page.evaluate(() => document.activeElement.textContent) === 'Create a test token', 'Arrow key moves between tabs');
  await page.keyboard.press('ArrowLeft');

  // XSS in real browser
  const evil = '<img src=x onerror="window.__pwned=1">';
  const bad = Buffer.from(JSON.stringify({ alg: 'HS256', kid: evil })).toString('base64url') + '.' + Buffer.from(JSON.stringify({ [evil]: '<svg onload=alert(1)>' })).toString('base64url') + '.abc';
  await page.locator('textarea').first().fill(bad);
  await page.waitForTimeout(600);
  ok(await page.evaluate(() => window.__pwned === undefined && document.querySelectorAll('.aptdot-jwt-app img, .aptdot-jwt-app svg').length === 0), 'Hostile token is inert in a real browser');

  // Network: nothing left the page except the simulated key fetches
  const external = requests.filter((u) => !u.startsWith('https://www.aptdot.com/tools/jwt-decoder/') && !u.startsWith('https://auth.example.com/') && !u.startsWith('https://nocors.example.com/') && !u.startsWith('data:'));
  ok(external.length === 0, 'No other network requests: ' + external.join(', '));
  ok(await page.evaluate(() => { try { return localStorage.length === 0 && sessionStorage.length === 0 && document.cookie === ''; } catch (e) { return true; } }), 'Nothing written to storage or cookies');
  const unexpected = errors.filter((e) => !/Failed to load resource: net::ERR_FAILED/.test(e)); // the deliberately blocked CORS simulation
  ok(unexpected.length === 0, 'No console errors: ' + unexpected.join(' | '));

  // Mobile layout
  const m = await browser.newContext({ viewport: { width: 390, height: 844 }, isMobile: true });
  const mp = await m.newPage();
  await mp.route('https://www.aptdot.com/tools/jwt-decoder/', (r) => r.fulfill({ status: 200, contentType: 'text/html', body: html }));
  await mp.goto('https://www.aptdot.com/tools/jwt-decoder/');
  await mp.selectOption('.jwt-toolbar select', 'idtoken');
  await mp.waitForTimeout(2500);
  const overflow = await mp.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  ok(overflow <= 0, `Mobile: no horizontal page scroll (${overflow}px)`);
  await mp.screenshot({ path: path.join(shots, 'mobile-idtoken.png'), fullPage: true });
  await browser.close();
  console.log(`${pass} passed, ${fail} failed`);
  if (fail) { console.log(failures.map((f) => '  - ' + f).join('\n')); process.exit(1); }
})().catch((e) => { console.error(e); process.exit(1); });
