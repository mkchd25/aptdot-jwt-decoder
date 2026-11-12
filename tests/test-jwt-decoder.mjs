// Test suite for src/jwt-decoder.js
// Unit, interop and safety tests. Usage: npm test   (or node tests/test-jwt-decoder.mjs [path to jwt-decoder.js] [node_modules dir])
import fs from 'fs';
import path from 'path';
import os from 'os';
import { execFileSync } from 'child_process';
import { createRequire } from 'module';
import { fileURLToPath, pathToFileURL } from 'url';

const repoRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const enginePath = process.argv[2] || path.join(repoRoot, 'src', 'jwt-decoder.js');
const nm = process.argv[3] || path.join(repoRoot, 'node_modules');
const require = createRequire(path.join(nm, 'x.js'));
const jose = await import(pathToFileURL(path.join(nm, 'jose/dist/webapi/index.js')).href);
const jsonwebtoken = require('jsonwebtoken');
const { JSDOM } = require('jsdom');

const src = fs.readFileSync(enginePath, 'utf8');
const dom = new JSDOM('<!doctype html><html><body><div class="aptdot-jwt-app"></div></body></html>', { runScripts: 'outside-only', url: 'https://www.aptdot.com/tools/jwt-decoder/' });
const w = dom.window;
Object.defineProperty(w, 'crypto', { value: globalThis.crypto });
w.TextEncoder = TextEncoder;
w.TextDecoder = TextDecoder;
w.eval(src);
const J = w.AptdotJwt;

let pass = 0, fail = 0;
const failures = [];
function ok(cond, name) {
  if (cond) pass++;
  else { fail++; failures.push(name); }
}
const te = new TextEncoder();
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'jwtt-'));
const now = Math.floor(Date.now() / 1000);
const claims = { iss: 'https://auth.example.com/', sub: 'u1', aud: 'api', iat: now, exp: now + 600, name: 'Zürich ✓ 日本' };

async function ver(token, opts) {
  const n = J.normalizeToken(token);
  const d = J.decode(n.token);
  return J.verify(d, opts);
}

// ---------- 1. jose-signed tokens verified with every key format
const ASYM = { RS256: 'RS256', RS384: 'RS384', RS512: 'RS512', PS256: 'PS256', PS384: 'PS384', PS512: 'PS512', ES256: 'ES256', ES384: 'ES384', ES512: 'ES512', EdDSA: 'EdDSA', Ed25519: 'Ed25519' };
for (const alg of Object.keys(ASYM)) {
  const genAlg = alg === 'Ed25519' ? 'EdDSA' : alg;
  const { publicKey, privateKey } = await jose.generateKeyPair(genAlg, { extractable: true, crv: genAlg === 'EdDSA' ? 'Ed25519' : undefined });
  const spki = await jose.exportSPKI(publicKey);
  const jwk = await jose.exportJWK(publicKey);
  const kid = await jose.calculateJwkThumbprint(jwk);
  const pkcs8 = await jose.exportPKCS8(privateKey);
  const token = await new jose.SignJWT(claims).setProtectedHeader({ alg, kid, typ: 'JWT' }).sign(privateKey);
  const r1 = await ver(token, { mode: 'key', keyText: spki });
  ok(r1.status === 'valid', `${alg} SPKI PEM verifies (${r1.message})`);
  const r2 = await ver(token, { mode: 'key', keyText: JSON.stringify(jwk) });
  ok(r2.status === 'valid', `${alg} JWK verifies`);
  const other = await jose.generateKeyPair(genAlg, { extractable: true, crv: genAlg === 'EdDSA' ? 'Ed25519' : undefined });
  const ojwk = await jose.exportJWK(other.publicKey);
  ojwk.kid = 'other';
  const r3 = await ver(token, { mode: 'key', keyText: JSON.stringify({ keys: [ojwk, { ...jwk, kid }] }) });
  ok(r3.status === 'valid' && r3.notes.join(' ').includes(kid), `${alg} JWKS picks key by kid`);
  const tokNoKid = await new jose.SignJWT(claims).setProtectedHeader({ alg }).sign(privateKey);
  const r4 = await ver(tokNoKid, { mode: 'key', keyText: JSON.stringify({ keys: [ojwk, jwk] }) });
  ok(r4.status === 'valid', `${alg} JWKS without kid tries each key`);
  const r5 = await ver(token, { mode: 'key', keyText: await jose.exportSPKI(other.publicKey) });
  ok(r5.status === 'invalid', `${alg} wrong key is rejected`);
  const parts = token.split('.');
  const tampered = parts[0] + '.' + J.bytesToB64url(te.encode(JSON.stringify({ ...claims, sub: 'admin' }))) + '.' + parts[2];
  const r6 = await ver(tampered, { mode: 'key', keyText: spki });
  ok(r6.status === 'invalid', `${alg} tampered payload is rejected`);
  const r7 = await ver(token, { mode: 'key', keyText: pkcs8 });
  ok(r7.status === 'valid' && r7.notes.join(' ').includes('private key'), `${alg} private PKCS#8 used for public part with warning`);
  const r8 = await ver(token, { mode: 'secret', secret: 'x'.repeat(40), encoding: 'utf8' });
  ok(r8.status === 'error', `${alg} refuses secret mode`);
  const r9 = await ver(token, { mode: 'key', keyText: JSON.stringify({ keys: [ojwk] }) });
  ok(r9.status === 'error' && /No key in the set has kid/.test(r9.message), `${alg} JWKS without matching kid explains`);
}

// ---------- 2. Cross-family mismatch (algorithm confusion guard)
{
  const rsa = await jose.generateKeyPair('RS256', { extractable: true });
  const ec = await jose.generateKeyPair('ES256', { extractable: true });
  const tok = await new jose.SignJWT(claims).setProtectedHeader({ alg: 'RS256' }).sign(rsa.privateKey);
  const r = await ver(tok, { mode: 'key', keyText: await jose.exportSPKI(ec.publicKey) });
  ok(r.status === 'error' && /EC key/.test(r.message), 'RS256 token with EC key gives a clear mismatch error');
  const p384 = await jose.generateKeyPair('ES384', { extractable: true });
  const tok2 = await new jose.SignJWT(claims).setProtectedHeader({ alg: 'ES256' }).sign(ec.privateKey);
  const r2 = await ver(tok2, { mode: 'key', keyText: await jose.exportSPKI(p384.publicKey) });
  ok(r2.status === 'error' && /curve/.test(r2.message), 'ES256 token with P-384 key gives a curve error');
  // classic attack: HS256 token whose secret is the RSA public key PEM
  const pem = await jose.exportSPKI(rsa.publicKey);
  const forged = await new jose.SignJWT(claims).setProtectedHeader({ alg: 'HS256' }).sign(te.encode(pem));
  const r3 = await ver(forged, { mode: 'secret', secret: pem, encoding: 'utf8' });
  ok(r3.status === 'valid' && r3.warnings.some((x) => /algorithm-confusion/.test(x)), 'Public key used as HMAC secret is flagged as algorithm confusion');
}

// ---------- 3. OpenSSL key formats: certificate, PKCS#1, traditional private key
{
  const kp = path.join(tmp, 'k.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', kp, '-out', path.join(tmp, 'c.pem'), '-days', '30', '-subj', '/CN=test.example.com'], { stdio: 'ignore' });
  const keyPem = fs.readFileSync(kp, 'utf8');
  const certPem = fs.readFileSync(path.join(tmp, 'c.pem'), 'utf8');
  const pkcs1 = execFileSync('openssl', ['rsa', '-in', kp, '-RSAPublicKey_out'], { stdio: ['pipe', 'pipe', 'ignore'] }).toString();
  const priv = await jose.importPKCS8(keyPem, 'RS256');
  const tok = await new jose.SignJWT(claims).setProtectedHeader({ alg: 'RS256' }).sign(priv);
  const rc = await ver(tok, { mode: 'key', keyText: certPem });
  ok(rc.status === 'valid' && rc.notes.join(' ').includes('certificate'), 'X.509 certificate verifies (RSA)');
  const rp = await ver(tok, { mode: 'key', keyText: pkcs1 });
  ok(pkcs1.includes('BEGIN RSA PUBLIC KEY') && rp.status === 'valid', 'PKCS#1 RSA PUBLIC KEY verifies');
  // EC certificate with no version field variations
  const ekp = path.join(tmp, 'ek.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', ekp, '-out', path.join(tmp, 'ec.pem'), '-days', '30', '-subj', '/CN=ec.example.com'], { stdio: 'ignore' });
  const epriv = await jose.importPKCS8(fs.readFileSync(ekp, 'utf8'), 'ES256');
  const etok = await new jose.SignJWT(claims).setProtectedHeader({ alg: 'ES256' }).sign(epriv);
  const re = await ver(etok, { mode: 'key', keyText: fs.readFileSync(path.join(tmp, 'ec.pem'), 'utf8') });
  ok(re.status === 'valid', 'X.509 certificate verifies (EC P-256)');
  const trad = execFileSync('openssl', ['rsa', '-in', kp, '-traditional'], { stdio: ['pipe', 'pipe', 'ignore'] }).toString();
  const rt = await ver(tok, { mode: 'key', keyText: trad });
  ok(rt.status === 'error' && /openssl pkcs8/.test(rt.message), 'Traditional RSA PRIVATE KEY gives conversion advice');
  // 1024-bit RSA warning
  execFileSync('openssl', ['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:1024', '-out', path.join(tmp, 'w.pem')], { stdio: 'ignore' });
  const weakPem = fs.readFileSync(path.join(tmp, 'w.pem'), 'utf8');
  const weakSigner = w.crypto ? null : null;
  const weakPub = execFileSync('openssl', ['pkey', '-in', path.join(tmp, 'w.pem'), '-pubout'], { stdio: ['pipe', 'pipe', 'ignore'] }).toString();
  const weakTok = jsonwebtoken.sign(claims, weakPem, { algorithm: 'RS256', allowInsecureKeySizes: true });
  const rw = await ver(weakTok, { mode: 'key', keyText: weakPub });
  ok(rw.status === 'valid' && rw.warnings.some((x) => /1024 bits/.test(x)), '1024-bit RSA key is flagged');
}

// ---------- 4. HMAC
for (const alg of ['HS256', 'HS384', 'HS512']) {
  const secret = 'k'.repeat(64);
  const tok = await new jose.SignJWT(claims).setProtectedHeader({ alg }).sign(te.encode(secret));
  ok((await ver(tok, { mode: 'secret', secret, encoding: 'utf8' })).status === 'valid', `${alg} verifies with UTF-8 secret`);
  ok((await ver(tok, { mode: 'secret', secret: secret + 'x', encoding: 'utf8' })).status === 'invalid', `${alg} wrong secret rejected`);
  const raw = crypto.getRandomValues(new Uint8Array(64));
  const tok2 = await new jose.SignJWT(claims).setProtectedHeader({ alg }).sign(raw);
  ok((await ver(tok2, { mode: 'secret', secret: J.bytesToB64url(raw), encoding: 'base64url' })).status === 'valid', `${alg} verifies with base64url secret`);
  ok((await ver(tok2, { mode: 'secret', secret: Buffer.from(raw).toString('base64'), encoding: 'base64' })).status === 'valid', `${alg} verifies with base64 secret`);
}
{
  const tok = await new jose.SignJWT(claims).setProtectedHeader({ alg: 'HS256' }).sign(te.encode('secret'));
  const r = await ver(tok, { mode: 'secret', secret: 'secret', encoding: 'utf8' });
  ok(r.status === 'valid' && r.warnings.some((x) => /RFC 7518/.test(x)) && r.warnings.some((x) => /short word/.test(x)), 'Weak HS256 secret is flagged');
}

// ---------- 5. Our signer is accepted by jose and jsonwebtoken
for (const alg of ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'Ed25519']) {
  let tok, key;
  if (alg.startsWith('HS')) {
    const secret = 'a-very-long-test-secret-for-hmac-signing-0123456789-abcdefghij';
    tok = await J.sign({ typ: 'JWT' }, claims, { alg, secret, encoding: 'utf8' });
    key = te.encode(secret);
  } else {
    const kp = await J.generateKeyPair(alg);
    tok = await J.sign({ typ: 'JWT', kid: kp.kid }, claims, { alg, privateKey: kp.privateKey });
    key = await jose.importJWK(kp.publicJwk, alg);
    ok(kp.kid === (await jose.calculateJwkThumbprint(kp.publicJwk)), `${alg} kid equals RFC 7638 thumbprint`);
    ok((await jose.importSPKI(kp.publicPem, alg)) !== null, `${alg} public PEM imports in jose`);
  }
  try {
    const { payload, protectedHeader } = await jose.jwtVerify(tok, key);
    ok(payload.name === claims.name && protectedHeader.alg === alg, `${alg} token from our signer verifies in jose`);
  } catch (e) {
    ok(false, `${alg} token from our signer verifies in jose: ${e.message}`);
  }
}
{
  const kp = await J.generateKeyPair('RS256');
  const tok = await J.sign({}, claims, { alg: 'RS256', privateKey: kp.privateKey });
  ok(!!jsonwebtoken.verify(tok, kp.publicPem, { algorithms: ['RS256'] }), 'RS256 from our signer verifies in jsonwebtoken');
  const kp2 = await J.generateKeyPair('ES256');
  const tok2 = await J.sign({}, claims, { alg: 'ES256', privateKey: kp2.privateKey });
  ok(!!jsonwebtoken.verify(tok2, kp2.publicPem, { algorithms: ['ES256'] }), 'ES256 from our signer verifies in jsonwebtoken');
  const pk = await J.importSigningKey('ES256', await jose.exportPKCS8((await jose.generateKeyPair('ES256', { extractable: true })).privateKey));
  ok(!!pk, 'Pasted PKCS#8 private key imports for signing');
}

// ---------- 6. Decoding edge cases
{
  const tok = await new jose.SignJWT(claims).setProtectedHeader({ alg: 'HS256' }).sign(te.encode('k'.repeat(32)));
  const n = J.normalizeToken('Authorization: Bearer "' + tok.slice(0, 20) + '\n  ' + tok.slice(20) + '"');
  ok(n.token === tok && n.notes.length === 4, 'Authorization header, quotes and line breaks are cleaned');
  const d = J.decode(tok);
  ok(d.kind === 'JWS' && d.payload.name === claims.name, 'Unicode payload decodes');
  ok(J.decode('abc').errors[0].includes('has 1'), 'One-part input explained');
  ok(J.decode('a.b').errors[0].includes('has 2'), 'Two-part input explained');
  const bad = J.decode(tok.replace('.', '!.'));
  ok(bad.errors.some((e) => /Invalid character "!"/.test(e)), 'Invalid base64url character reported with position');
  const std = J.decode('eyJhbGciOiJIUzI1NiJ9.' + Buffer.from('{"a":"???"}').toString('base64').replace(/=+$/, '') + '.x');
  ok(std.errors.some((e) => /standard base64/.test(e)) || std.payload, 'Standard base64 characters detected');
  const padded = J.decode(Buffer.from('{"alg":"HS256"}').toString('base64url') + '==.' + Buffer.from('{"a":1}').toString('base64url') + '.abc');
  ok(padded.padding.length === 1, 'Padding detected');
  const nonUtf = J.decode(Buffer.from('{"alg":"HS256"}').toString('base64url') + '.' + Buffer.from([0xff, 0xfe, 0x00]).toString('base64url') + '.abc');
  ok(nonUtf.errors.some((e) => /UTF-8/.test(e)), 'Non-UTF-8 payload reported');
  const dup = J.decode(Buffer.from('{"alg":"HS256","alg":"none"}').toString('base64url') + '.' + Buffer.from('{"sub":"a","sub":"admin"}').toString('base64url') + '.abc');
  const da = J.analyze(dup, { now });
  ok(dup.duplicates.header[0] === 'alg' && dup.duplicates.payload[0] === 'sub' && da.findings.some((f) => f.code === 'dup-claims') && da.findings.some((f) => f.code === 'dup-header'), 'Duplicate header and claim names detected');
  const proto = J.decode(Buffer.from('{"alg":"HS256"}').toString('base64url') + '.' + Buffer.from('{"__proto__":{"polluted":1},"constructor":{"prototype":{"x":1}}}').toString('base64url') + '.abc');
  ok(({}).polluted === undefined && w.Object.prototype.polluted === undefined && Object.keys(proto.payload).includes('__proto__'), '__proto__ is kept as data and pollutes nothing');
  const jwe = 'eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0.a.b.c.d';
  const dj = J.decode(jwe);
  ok(dj.kind === 'JWE' && dj.header.enc === 'A256GCM' && J.analyze(dj, { now }).findings[0].code === 'jwe', 'JWE recognised, header shown');
  const notJson = J.decode(Buffer.from('{"alg":"HS256"}').toString('base64url') + '.' + Buffer.from('hello').toString('base64url') + '.abc');
  ok(notJson.payloadText === 'hello' && notJson.errors.some((e) => /not valid JSON/.test(e)), 'Non-JSON payload shown as text with error');
  const arr = J.decode(Buffer.from('{"alg":"HS256"}').toString('base64url') + '.' + Buffer.from('[1,2]').toString('base64url') + '.abc');
  ok(arr.errors.some((e) => /must be a JSON object/.test(e)), 'Array payload rejected as claims set');
  const jsonErr = J.decode(Buffer.from('{"alg":"HS256",}').toString('base64url') + '.e30.abc');
  ok(jsonErr.errors.some((e) => /line 1, column/.test(e)), 'Header JSON error has line and column');
  ok(J.normalizeToken('x'.repeat(100001)).error, 'Over-long input refused');
  // fuzz: never throws
  let threw = 0;
  for (let i = 0; i < 3000; i++) {
    const len = Math.floor(Math.random() * 120);
    let s = '';
    for (let k = 0; k < len; k++) s += String.fromCharCode(Math.random() < 0.8 ? 32 + Math.floor(Math.random() * 95) : Math.floor(Math.random() * 0x3000));
    if (Math.random() < 0.5) s = s.replace(/[^A-Za-z0-9_\-.]/g, '') + '.' + J.bytesToB64url(te.encode(s.slice(0, 20))) + '.x';
    try { const dd = J.decode(J.normalizeToken(s).token); if (dd.header) J.analyze(dd, { now }); } catch (e) { threw++; }
  }
  ok(threw === 0, `Fuzz: 3000 random inputs never throw (${threw} threw)`);
}

// ---------- 7. Unsigned, crit, b64, DER ECDSA
{
  const none = await J.sign({}, claims, { alg: 'none' });
  const d = J.decode(none);
  const a = J.analyze(d, { now });
  ok(a.findings.some((f) => f.code === 'alg-none' && f.level === 'danger'), 'alg none is critical');
  ok((await J.verify(d, { mode: 'secret', secret: 'x', encoding: 'utf8' })).status === 'invalid', 'alg none never verifies');
  const noneSig = J.decode(none + 'AAAA');
  ok(J.analyze(noneSig, { now }).findings.some((f) => f.code === 'none-sig'), 'alg none with a signature is an error');
  const NONE = J.decode(Buffer.from('{"alg":"NoNe"}').toString('base64url') + '.e30.');
  ok(J.analyze(NONE, { now }).findings.some((f) => f.code === 'alg-none'), 'Mixed-case "NoNe" is caught');
  const secret = 'k'.repeat(32);
  const crit = await new jose.SignJWT(claims).setProtectedHeader({ alg: 'HS256', crit: ['exp'], exp: 1 }).sign(te.encode(secret)).catch(() => null);
  const critTok = crit || (await J.sign({ crit: ['foo'], foo: 1 }, claims, { alg: 'HS256', secret, encoding: 'utf8' }));
  ok((await ver(critTok, { mode: 'secret', secret, encoding: 'utf8' })).status === 'invalid', 'Unknown crit parameters force rejection');
  const ec = await jose.generateKeyPair('ES256', { extractable: true });
  const etok = await new jose.SignJWT(claims).setProtectedHeader({ alg: 'ES256' }).sign(ec.privateKey);
  const raw = Buffer.from(etok.split('.')[2], 'base64url');
  const toInt = (b) => { let i = 0; while (i < b.length - 1 && b[i] === 0) i++; b = b.subarray(i); return b[0] & 0x80 ? Buffer.concat([Buffer.from([0]), b]) : b; };
  const r = toInt(raw.subarray(0, 32)), s = toInt(raw.subarray(32));
  const der = Buffer.concat([Buffer.from([0x30, r.length + s.length + 4, 0x02, r.length]), r, Buffer.from([0x02, s.length]), s]);
  const derTok = etok.split('.').slice(0, 2).join('.') + '.' + der.toString('base64url');
  const rd = await ver(derTok, { mode: 'key', keyText: await jose.exportSPKI(ec.publicKey) });
  ok(rd.status === 'invalid' && /DER-encoded/.test(rd.message), 'DER-encoded ECDSA signature explained');
}

// ---------- 8. Findings
{
  const h = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const mk = (head, pay) => J.decode(h(head) + '.' + h(pay) + '.abc');
  const codes = (head, pay, t) => J.analyze(mk(head, pay), { now: t || now, skew: 0 }).findings.map((f) => f.code);
  ok(codes({ alg: 'HS256' }, { exp: now - 10 }).includes('expired'), 'Expired detected');
  ok(!codes({ alg: 'HS256' }, { exp: now - 10 }).includes('expired') === false && J.analyze(mk({ alg: 'HS256' }, { exp: now - 10 }), { now, skew: 60 }).findings.every((f) => f.code !== 'expired'), 'Clock tolerance respected');
  ok(codes({ alg: 'HS256' }, { exp: now + 999, nbf: now + 500 }).includes('nbf'), 'Not-yet-valid detected');
  ok(codes({ alg: 'HS256' }, { iat: now + 500, exp: now + 900 }).includes('iat-future'), 'iat in future detected');
  ok(codes({ alg: 'HS256' }, { sub: 'x' }).includes('no-exp'), 'Missing exp detected');
  ok(codes({ alg: 'HS256' }, { exp: Date.now() + 1e6 }).includes('time-ms'), 'Milliseconds detected');
  ok(codes({ alg: 'HS256' }, { exp: String(now + 100) }).includes('time-string'), 'String time detected');
  ok(codes({ alg: 'HS256' }, { iat: now, exp: now + 86400 * 30 }).includes('lifetime'), 'Long lifetime detected');
  ok(codes({ alg: 'HS256', kid: '../../dev/null' }, {}).includes('kid'), 'kid traversal detected');
  ok(codes({ alg: 'HS256', kid: "x' UNION SELECT" }, {}).includes('kid'), 'kid SQL injection characters detected');
  ok(codes({ alg: 'RS256', jku: 'https://evil' }, {}).includes('jku'), 'jku detected');
  ok(codes({ alg: 'RS256', jwk: { kty: 'RSA' } }, {}).includes('jwk'), 'Embedded jwk detected');
  ok(codes({ alg: 'HS256' }, { email: 'a@b.c', password: 'x' }).includes('pii'), 'Personal data detected');
  ok(codes({ alg: 'HS256', typ: 'JWT' }, { scope: 'a', client_id: 'c' }).includes('typ'), 'Access token typ advice');
  ok(!codes({ alg: 'HS256', typ: 'at+jwt' }, { scope: 'a' }).includes('typ'), 'at+jwt accepted');
  ok(codes({ alg: 'EdDSA' }, {}).includes('eddsa'), 'EdDSA deprecation note (RFC 9864)');
  ok(codes({ alg: 'ES256K' }, {}).includes('alg-unsupported'), 'ES256K explained as unsupported');
  ok(codes({ alg: 'hs256' }, {}).includes('alg-unknown'), 'Case-sensitive alg names');
  ok(codes({ alg: 'HS256', zip: 'DEF' }, {}).includes('zip'), 'zip in JWS flagged');
  ok(codes({}, {}).includes('alg-missing'), 'Missing alg flagged');
  ok(codes({ alg: 'HS256' }, { iss: 'https://a', aud: 'x', iat: now, exp: now + 300 }).includes('clean'), 'Clean token gets OK');
  const rows = J.analyze(mk({ alg: 'HS256' }, { exp: now + 3600, custom: 1 }), { now }).rows.payload;
  ok(rows[0].detail.includes('UTC') && rows[0].detail.includes('in 1 h') && rows[1].label === 'Custom', 'Claim rows explain times and custom claims');
}

// ---------- 9. Samples
for (const name of ['access', 'idtoken', 'es256', 'ed25519', 'expired', 'none', 'risky']) {
  const s = await J.makeSample(name);
  const d = J.decode(s.token);
  const r = await J.verify(d, s.verify);
  const a = J.analyze(d, { now: Math.floor(Date.now() / 1000) });
  const expectValid = name !== 'none';
  ok((r.status === 'valid') === expectValid, `Sample ${name}: signature ${r.status}`);
  if (name === 'expired') ok(a.findings.some((f) => f.code === 'expired'), 'Sample expired is expired');
  if (name === 'risky') ok(['kid', 'jku', 'no-exp', 'pii', 'time-string'].every((c) => a.findings.some((f) => f.code === c)), 'Sample risky shows all intended warnings');
  if (name === 'access') ok(a.findings.some((f) => f.code === 'clean') || !a.findings.some((f) => f.level === 'danger'), 'Sample access token has no critical findings');
}

// ---------- 10. UI: build, XSS, sample, verify display (jsdom)
{
  const root = w.document.querySelector('.aptdot-jwt-app');
  ok(root.getAttribute('data-ready') === '1' && root.querySelector('textarea'), 'App builds into the shortcode container');
  const evil = '<img src=x onerror="window.__pwned=1">';
  const head = Buffer.from(JSON.stringify({ alg: 'HS256', kid: evil, typ: '<script>' })).toString('base64url');
  const pay = Buffer.from(JSON.stringify({ [evil]: evil, sub: '</pre><b>x</b>' })).toString('base64url');
  const ta = root.querySelector('textarea');
  ta.value = head + '.' + pay + '.abc';
  ta.dispatchEvent(new w.Event('input'));
  await new Promise((r) => setTimeout(r, 400));
  ok(root.querySelectorAll('img, script, b').length === 0 && w.__pwned === undefined && root.textContent.includes(evil), 'Hostile header and claims render as text only');
  const sel = root.querySelector('select');
  sel.value = 'access';
  sel.dispatchEvent(new w.Event('change'));
  await new Promise((r) => setTimeout(r, 800));
  const verifyText = root.querySelector('.jwt-verify').textContent;
  ok(/Signature verified/.test(verifyText), 'Sample in the UI shows a verified signature');
  ok(root.querySelector('.jwt-status').textContent.includes('Signed JWT (HS256)'), 'Status line shows algorithm');
  ok(!/localStorage|sessionStorage|indexedDB|document\.cookie|sendBeacon|XMLHttpRequest/.test(src), 'Engine uses no storage, cookies, beacons or XHR');
  ok((src.match(/fetch\(/g) || []).length === 1, 'Exactly one fetch() call (the user-triggered key fetch)');
  ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/.test(src), 'No innerHTML, document.write, eval or new Function');
}

fs.rmSync(tmp, { recursive: true, force: true });
console.log(`\n${pass} passed, ${fail} failed`);
if (fail) { console.log(failures.map((f) => '  - ' + f).join('\n')); process.exit(1); }
