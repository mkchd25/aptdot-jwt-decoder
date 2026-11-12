/*!
 * Aptdot JWT Decoder & Verifier 1.0.0
 * Runs entirely in the browser. Tokens and keys are never stored or sent anywhere;
 * the only network request is the optional "Fetch keys" action, made after the user clicks it.
 * Rules: ES5 syntax only; user-supplied text is only ever written with textContent.
 */
(function () {
  'use strict';

  var MAX_INPUT = 100000;
  var DATASET_TEST_KEY = 'aptdot-public-test-key-NEVER-use-in-production-2026';

  /* ------------------------------------------------------------------ *
   * Bytes and encodings
   * ------------------------------------------------------------------ */
  var B64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  var B64_LOOKUP = {};
  (function () {
    for (var i = 0; i < 64; i++) B64_LOOKUP[B64_ALPHABET.charAt(i)] = i;
    B64_LOOKUP['-'] = 62;
    B64_LOOKUP._ = 63;
  })();

  // Strict base64url decoder. Returns {bytes} or {error, index}.
  function b64urlToBytes(str, allowStandard) {
    var padded = false;
    var s = str;
    var pad = s.indexOf('=');
    if (pad !== -1) {
      if (!/^=+$/.test(s.slice(pad)) || s.length - pad > 2) {
        return { error: 'Unexpected "=" inside the text', index: pad };
      }
      padded = true;
      s = s.slice(0, pad);
    }
    for (var i = 0; i < s.length; i++) {
      var ch = s.charAt(i);
      if (ch === '+' || ch === '/') {
        if (!allowStandard) return { error: 'Character "' + ch + '" belongs to standard base64, not base64url', index: i };
        ch = ch === '+' ? '-' : '_';
      }
      if (!B64_LOOKUP.hasOwnProperty(ch)) return { error: 'Invalid character "' + ch + '"', index: i };
    }
    if (allowStandard) s = s.replace(/\+/g, '-').replace(/\//g, '_');
    if (s.length % 4 === 1) return { error: 'Invalid length (one character too many or too few)', index: s.length - 1 };
    var out = new Uint8Array(Math.floor(s.length * 3 / 4));
    var o = 0;
    var buf = 0;
    var bits = 0;
    for (var j = 0; j < s.length; j++) {
      buf = (buf << 6) | B64_LOOKUP[s.charAt(j)];
      bits += 6;
      if (bits >= 8) {
        bits -= 8;
        out[o++] = (buf >> bits) & 255;
      }
    }
    return { bytes: out, padded: padded };
  }

  function bytesToB64url(bytes) {
    var out = '';
    var i;
    for (i = 0; i + 2 < bytes.length; i += 3) {
      var n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
      out += B64_ALPHABET.charAt((n >> 18) & 63) + B64_ALPHABET.charAt((n >> 12) & 63) +
        B64_ALPHABET.charAt((n >> 6) & 63) + B64_ALPHABET.charAt(n & 63);
    }
    if (bytes.length - i === 1) {
      var a = bytes[i] << 16;
      out += B64_ALPHABET.charAt((a >> 18) & 63) + B64_ALPHABET.charAt((a >> 12) & 63);
    } else if (bytes.length - i === 2) {
      var b = (bytes[i] << 16) | (bytes[i + 1] << 8);
      out += B64_ALPHABET.charAt((b >> 18) & 63) + B64_ALPHABET.charAt((b >> 12) & 63) + B64_ALPHABET.charAt((b >> 6) & 63);
    }
    return out.replace(/\+/g, '-').replace(/\//g, '_');
  }

  function bytesToB64(bytes) {
    var s = bytesToB64url(bytes).replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    return s;
  }

  function anyB64ToBytes(str) {
    var s = String(str).replace(/\s+/g, '');
    var r = b64urlToBytes(s.replace(/\+/g, '-').replace(/\//g, '_'), false);
    return r.error ? null : r.bytes;
  }

  function utf8Encode(str) {
    return new TextEncoder().encode(str);
  }

  function utf8Decode(bytes) {
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch (e) {
      return null;
    }
  }

  function concatBytes(list) {
    var len = 0;
    var i;
    for (i = 0; i < list.length; i++) len += list[i].length;
    var out = new Uint8Array(len);
    var o = 0;
    for (i = 0; i < list.length; i++) {
      out.set(list[i], o);
      o += list[i].length;
    }
    return out;
  }

  function bytesToHex(bytes, max) {
    var out = [];
    var n = Math.min(bytes.length, max || bytes.length);
    for (var i = 0; i < n; i++) out.push((bytes[i] < 16 ? '0' : '') + bytes[i].toString(16));
    return out.join('');
  }

  /* ------------------------------------------------------------------ *
   * JSON parser that keeps key order, reports duplicate names and exact
   * error positions, and never touches Object.prototype.
   * ------------------------------------------------------------------ */
  function parseJson(text) {
    var i = 0;
    var line = 1;
    var col = 1;
    var duplicates = [];

    function fail(msg) {
      var e = new Error(msg);
      e.jsonLine = line;
      e.jsonCol = col;
      throw e;
    }
    function adv() {
      var ch = text.charAt(i++);
      if (ch === '\n') {
        line++;
        col = 1;
      } else {
        col++;
      }
      return ch;
    }
    function ws() {
      while (i < text.length) {
        var ch = text.charAt(i);
        if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r') adv();
        else break;
      }
    }
    function str() {
      adv(); // opening quote
      var out = '';
      for (;;) {
        if (i >= text.length) fail('Unterminated string');
        var ch = adv();
        if (ch === '"') return out;
        if (ch === '\\') {
          var e = adv();
          if (e === '"' || e === '\\' || e === '/') out += e;
          else if (e === 'b') out += '\b';
          else if (e === 'f') out += '\f';
          else if (e === 'n') out += '\n';
          else if (e === 'r') out += '\r';
          else if (e === 't') out += '\t';
          else if (e === 'u') {
            var hex = text.substr(i, 4);
            if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail('Invalid \\u escape');
            for (var k = 0; k < 4; k++) adv();
            out += String.fromCharCode(parseInt(hex, 16));
          } else fail('Invalid escape \\' + e);
        } else if (ch < ' ') {
          fail('Control character inside a string');
        } else {
          out += ch;
        }
      }
    }
    function num() {
      var m = /^-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?/.exec(text.slice(i));
      if (!m) fail('Invalid number');
      for (var k = 0; k < m[0].length; k++) adv();
      return parseFloat(m[0]);
    }
    function val(path) {
      ws();
      if (i >= text.length) fail('Unexpected end of input');
      var ch = text.charAt(i);
      if (ch === '{') return obj(path);
      if (ch === '[') return arr(path);
      if (ch === '"') return str();
      if (ch === '-' || (ch >= '0' && ch <= '9')) return num();
      if (text.substr(i, 4) === 'true') { for (var a = 0; a < 4; a++) adv(); return true; }
      if (text.substr(i, 5) === 'false') { for (var b = 0; b < 5; b++) adv(); return false; }
      if (text.substr(i, 4) === 'null') { for (var c = 0; c < 4; c++) adv(); return null; }
      fail('Unexpected character "' + ch + '"');
    }
    function obj(path) {
      adv();
      var o = {};
      var seen = {};
      ws();
      if (text.charAt(i) === '}') { adv(); return o; }
      for (;;) {
        ws();
        if (text.charAt(i) !== '"') fail('Expected a property name in double quotes');
        var k = str();
        ws();
        if (text.charAt(i) !== ':') fail('Expected ":" after property name');
        adv();
        var v = val(path.concat([k]));
        if (Object.prototype.hasOwnProperty.call(seen, k)) duplicates.push(path.concat([k]).join('.'));
        seen[k] = true;
        Object.defineProperty(o, k, { value: v, enumerable: true, writable: true, configurable: true });
        ws();
        var ch = adv();
        if (ch === '}') return o;
        if (ch !== ',') fail('Expected "," or "}"');
      }
    }
    function arr(path) {
      adv();
      var a = [];
      ws();
      if (text.charAt(i) === ']') { adv(); return a; }
      for (;;) {
        a.push(val(path.concat([String(a.length)])));
        ws();
        var ch = adv();
        if (ch === ']') return a;
        if (ch !== ',') fail('Expected "," or "]"');
      }
    }
    try {
      var value = val([]);
      ws();
      if (i < text.length) fail('Unexpected text after the JSON value');
      return { value: value, duplicates: duplicates };
    } catch (e) {
      return { error: e.message, line: e.jsonLine, col: e.jsonCol };
    }
  }

  function isPlainObject(v) {
    return v !== null && typeof v === 'object' && !Array.isArray(v);
  }

  /* ------------------------------------------------------------------ *
   * Algorithms
   * ------------------------------------------------------------------ */
  var ALGS = {
    HS256: { family: 'HMAC', hash: 'SHA-256', size: 32 },
    HS384: { family: 'HMAC', hash: 'SHA-384', size: 48 },
    HS512: { family: 'HMAC', hash: 'SHA-512', size: 64 },
    RS256: { family: 'RSA', name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    RS384: { family: 'RSA', name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' },
    RS512: { family: 'RSA', name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' },
    PS256: { family: 'RSA', name: 'RSA-PSS', hash: 'SHA-256', salt: 32 },
    PS384: { family: 'RSA', name: 'RSA-PSS', hash: 'SHA-384', salt: 48 },
    PS512: { family: 'RSA', name: 'RSA-PSS', hash: 'SHA-512', salt: 64 },
    ES256: { family: 'EC', curve: 'P-256', hash: 'SHA-256', sigLen: 64 },
    ES384: { family: 'EC', curve: 'P-384', hash: 'SHA-384', sigLen: 96 },
    ES512: { family: 'EC', curve: 'P-521', hash: 'SHA-512', sigLen: 132 },
    Ed25519: { family: 'OKP', curve: 'Ed25519' },
    EdDSA: { family: 'OKP', curve: 'Ed25519' }
  };
  var KNOWN_UNSUPPORTED = { ES256K: 'secp256k1 is not available in browser Web Crypto', Ed448: 'Ed448 is not available in browser Web Crypto' };
  var JWE_ALGS = /^(RSA1_5|RSA-OAEP(-256|-384|-512)?|A(128|192|256)KW|dir|ECDH-ES(\+A(128|192|256)KW)?|A(128|192|256)GCMKW|PBES2-HS(256\+A128|384\+A192|512\+A256)KW)$/;

  function subtle() {
    return (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) ||
      (typeof crypto !== 'undefined' && crypto.subtle) || null;
  }

  /* ------------------------------------------------------------------ *
   * Token input and decoding
   * ------------------------------------------------------------------ */
  function normalizeToken(raw) {
    var notes = [];
    var s = String(raw == null ? '' : raw);
    if (s.length > MAX_INPUT) return { token: '', notes: [], error: 'Input is longer than ' + MAX_INPUT + ' characters.' };
    s = s.replace(/^\s+|\s+$/g, '');
    if (/^authorization\s*:/i.test(s)) {
      s = s.replace(/^authorization\s*:\s*/i, '');
      notes.push('Removed the "Authorization:" header name.');
    }
    var scheme = /^(bearer|dpop|jwt)\s+/i.exec(s);
    if (scheme) {
      s = s.slice(scheme[0].length);
      notes.push('Removed the "' + scheme[1] + '" prefix.');
    }
    if (s.length > 1 && /^["'`]/.test(s) && s.charAt(s.length - 1) === s.charAt(0)) {
      s = s.slice(1, -1);
      notes.push('Removed surrounding quotes.');
    }
    if (/\s/.test(s)) {
      s = s.replace(/\s+/g, '');
      notes.push('Removed spaces and line breaks inside the token.');
    }
    return { token: s, notes: notes };
  }

  function decodeSegment(seg, name, result, json) {
    if (seg === '') return { empty: true };
    var b = b64urlToBytes(seg, false);
    if (b.error) {
      result.errors.push(name + ': ' + b.error + ' at position ' + (b.index + 1) + '.');
      return null;
    }
    if (b.padded) result.padding.push(name);
    if (!json) return { bytes: b.bytes };
    var text = utf8Decode(b.bytes);
    if (text === null) {
      result.errors.push(name + ': decoded bytes are not valid UTF-8 text.');
      return { bytes: b.bytes };
    }
    var p = parseJson(text);
    if (p.error) return { bytes: b.bytes, text: text, jsonError: p };
    return { bytes: b.bytes, text: text, value: p.value, duplicates: p.duplicates };
  }

  function decode(token) {
    var r = { kind: null, segments: [], header: null, payload: null, payloadText: null, signature: null,
      errors: [], padding: [], duplicates: { header: [], payload: [] } };
    if (!token) {
      r.errors.push('Paste a token to decode it.');
      return r;
    }
    var parts = token.split('.');
    r.segments = parts;
    if (parts.length === 5) r.kind = 'JWE';
    else if (parts.length === 3) r.kind = 'JWS';
    else {
      r.errors.push('A JWT has 3 parts separated by dots (signed) or 5 parts (encrypted). This input has ' + parts.length + '.');
      return r;
    }
    var h = decodeSegment(parts[0], 'Header', r, true);
    if (!h || h.empty) {
      if (h && h.empty) r.errors.push('Header: the first part is empty.');
      return r;
    }
    if (h.jsonError) {
      r.errors.push('Header: not valid JSON (' + h.jsonError.error + ', line ' + h.jsonError.line + ', column ' + h.jsonError.col + ').');
      r.headerText = h.text;
      return r;
    }
    if (!isPlainObject(h.value)) {
      r.errors.push('Header: must be a JSON object.');
      return r;
    }
    r.header = h.value;
    r.duplicates.header = h.duplicates;
    if (r.kind === 'JWE') {
      r.signingInput = null;
      return r;
    }
    var unencoded = r.header.b64 === false;
    if (unencoded) {
      r.payloadText = parts[1];
    } else {
      var p = decodeSegment(parts[1], 'Payload', r, true);
      if (p && !p.empty) {
        if (p.value !== undefined) {
          r.payload = p.value;
          r.duplicates.payload = p.duplicates;
          if (!isPlainObject(p.value)) r.errors.push('Payload: valid JSON, but a JWT claims set must be a JSON object.');
        } else if (p.text !== undefined) {
          r.payloadText = p.text;
          if (r.header.cty && String(r.header.cty).toUpperCase() === 'JWT') r.nested = true;
          else r.errors.push('Payload: not valid JSON (' + p.jsonError.error + ', line ' + p.jsonError.line + ', column ' + p.jsonError.col + ').');
        }
      } else if (p && p.empty) {
        r.payloadText = '';
        r.errors.push('Payload: the second part is empty.');
      }
    }
    var s = decodeSegment(parts[2], 'Signature', r, false);
    r.signature = s && s.bytes ? s.bytes : new Uint8Array(0);
    r.signingInput = utf8Encode(parts[0] + '.' + parts[1]);
    return r;
  }

  /* ------------------------------------------------------------------ *
   * Claim and header dictionaries (IANA registries, own wording)
   * ------------------------------------------------------------------ */
  var CLAIMS = {
    iss: ['Issuer', 'Who created and signed the token, usually a URL. Check it against the issuer you trust.', 'RFC 7519 §4.1.1'],
    sub: ['Subject', 'Who the token is about, usually a user or client ID. Unique within the issuer.', 'RFC 7519 §4.1.2'],
    aud: ['Audience', 'Who the token is for. A service must reject tokens whose audience does not include it.', 'RFC 7519 §4.1.3'],
    exp: ['Expiration time', 'The token must not be accepted on or after this time.', 'RFC 7519 §4.1.4'],
    nbf: ['Not before', 'The token must not be accepted before this time.', 'RFC 7519 §4.1.5'],
    iat: ['Issued at', 'When the token was created.', 'RFC 7519 §4.1.6'],
    jti: ['JWT ID', 'A unique ID for this token, used to detect replays.', 'RFC 7519 §4.1.7'],
    nonce: ['Nonce', 'Value from the login request, echoed back so the client can detect replayed ID tokens.', 'OpenID Connect Core §2'],
    auth_time: ['Authentication time', 'When the user actually signed in.', 'OpenID Connect Core §2'],
    acr: ['Authentication context', 'How strong the sign-in was, as a reference agreed with the client.', 'OpenID Connect Core §2'],
    amr: ['Authentication methods', 'How the user signed in, for example pwd, otp or mfa.', 'OpenID Connect Core §2, RFC 8176'],
    azp: ['Authorized party', 'The client the ID token was issued to.', 'OpenID Connect Core §2'],
    at_hash: ['Access token hash', 'Half of a hash of the access token, binding it to this ID token.', 'OpenID Connect Core §2'],
    c_hash: ['Code hash', 'Half of a hash of the authorization code, binding it to this ID token.', 'OpenID Connect Core §3.3.2.11'],
    sid: ['Session ID', 'Identifies the sign-in session, used for logout.', 'OpenID Connect Front-Channel Logout §3'],
    cnf: ['Confirmation', 'The key the presenter must prove it holds (proof of possession, for example DPoP or mTLS).', 'RFC 7800 §3.1'],
    client_id: ['Client ID', 'The OAuth client the access token was issued to.', 'RFC 8693 §4.3, RFC 9068'],
    scope: ['Scope', 'Space-separated permissions granted to the token.', 'RFC 8693 §4.2, RFC 9068'],
    act: ['Actor', 'Who is acting on behalf of the subject (delegation).', 'RFC 8693 §4.1'],
    may_act: ['May act', 'Who is allowed to become the actor for this subject.', 'RFC 8693 §4.4'],
    roles: ['Roles', 'Roles held by the subject.', 'RFC 9068 §2.2.3.1'],
    groups: ['Groups', 'Groups the subject belongs to.', 'RFC 9068 §2.2.3.1'],
    entitlements: ['Entitlements', 'Individual entitlements of the subject.', 'RFC 9068 §2.2.3.1'],
    events: ['Security events', 'The events described by a Security Event Token.', 'RFC 8417 §2.2'],
    toe: ['Time of event', 'When the security event happened.', 'RFC 8417 §2.2'],
    txn: ['Transaction ID', 'Links related tokens and events.', 'RFC 8417 §2.2'],
    sub_jwk: ['Subject JWK', 'Public key for checking a self-issued ID token.', 'OpenID Connect Core §7.4'],
    name: ['Full name', 'The user\'s display name.', 'OpenID Connect Core §5.1'],
    given_name: ['Given name', 'First name.', 'OpenID Connect Core §5.1'],
    family_name: ['Family name', 'Surname.', 'OpenID Connect Core §5.1'],
    preferred_username: ['Preferred username', 'Short name the user wants to be shown. Not guaranteed unique.', 'OpenID Connect Core §5.1'],
    email: ['Email', 'The user\'s email address. Personal data, readable by anyone with the token.', 'OpenID Connect Core §5.1'],
    email_verified: ['Email verified', 'Whether the provider verified the email address.', 'OpenID Connect Core §5.1'],
    phone_number: ['Phone number', 'Personal data, readable by anyone with the token.', 'OpenID Connect Core §5.1'],
    phone_number_verified: ['Phone verified', 'Whether the provider verified the phone number.', 'OpenID Connect Core §5.1'],
    picture: ['Picture', 'URL of the user\'s profile picture.', 'OpenID Connect Core §5.1'],
    locale: ['Locale', 'The user\'s language and region, for example en-IN.', 'OpenID Connect Core §5.1'],
    zoneinfo: ['Time zone', 'The user\'s IANA time zone, for example Asia/Kolkata.', 'OpenID Connect Core §5.1'],
    updated_at: ['Updated at', 'When the user\'s profile was last changed.', 'OpenID Connect Core §5.1'],
    birthdate: ['Birthdate', 'Personal data, readable by anyone with the token.', 'OpenID Connect Core §5.1'],
    address: ['Address', 'Personal data, readable by anyone with the token.', 'OpenID Connect Core §5.1'],
    htm: ['HTTP method', 'The HTTP method of the request this DPoP proof is for.', 'RFC 9449 §4.2'],
    htu: ['HTTP URI', 'The URL of the request this DPoP proof is for.', 'RFC 9449 §4.2'],
    ath: ['Access token hash', 'Hash of the access token this DPoP proof is bound to.', 'RFC 9449 §4.2']
  };
  var TIME_CLAIMS = { exp: 1, nbf: 1, iat: 1, auth_time: 1, toe: 1, updated_at: 1 };
  var HEADER_PARAMS = {
    alg: ['Algorithm', 'How the token is signed (or, for JWE, how the key is encrypted).', 'RFC 7515 §4.1.1'],
    typ: ['Type', 'Media type of the token, for example JWT or at+jwt for access tokens.', 'RFC 7515 §4.1.9'],
    cty: ['Content type', 'Type of the payload. "JWT" means the payload is another token (nested JWT).', 'RFC 7515 §4.1.10'],
    kid: ['Key ID', 'Hint for which key verifies the token. Look it up in your own trusted key set.', 'RFC 7515 §4.1.4'],
    jku: ['JWK Set URL', 'URL of a key set. Never fetch keys from a URL taken from the token itself.', 'RFC 7515 §4.1.2'],
    jwk: ['Embedded key', 'A public key inside the header. Never verify a token with a key it carries itself.', 'RFC 7515 §4.1.3'],
    x5u: ['X.509 URL', 'URL of a certificate chain. Same risk as jku.', 'RFC 7515 §4.1.5'],
    x5c: ['X.509 chain', 'Certificate chain inside the header. Only trust it after validating the chain.', 'RFC 7515 §4.1.6'],
    x5t: ['Certificate thumbprint (SHA-1)', 'Identifies a certificate by its SHA-1 hash.', 'RFC 7515 §4.1.7'],
    'x5t#S256': ['Certificate thumbprint (SHA-256)', 'Identifies a certificate by its SHA-256 hash.', 'RFC 7515 §4.1.8'],
    crit: ['Critical', 'Header parameters the receiver must understand, or reject the token.', 'RFC 7515 §4.1.11'],
    b64: ['Base64url payload', 'false means the payload is not base64url-encoded (RFC 7797).', 'RFC 7797 §3'],
    enc: ['Content encryption', 'How the payload of an encrypted token (JWE) is encrypted.', 'RFC 7516 §4.1.2'],
    zip: ['Compression', 'Payload compression. Only defined for encrypted tokens (JWE).', 'RFC 7516 §4.1.3'],
    epk: ['Ephemeral public key', 'Sender\'s temporary key for ECDH key agreement (JWE).', 'RFC 7518 §4.6.1.1']
  };

  /* ------------------------------------------------------------------ *
   * Time helpers
   * ------------------------------------------------------------------ */
  function pad2(n) {
    return (n < 10 ? '0' : '') + n;
  }
  function isoUtc(sec) {
    var d = new Date(sec * 1000);
    if (isNaN(d.getTime())) return 'invalid date';
    return d.getUTCFullYear() + '-' + pad2(d.getUTCMonth() + 1) + '-' + pad2(d.getUTCDate()) + ' ' +
      pad2(d.getUTCHours()) + ':' + pad2(d.getUTCMinutes()) + ':' + pad2(d.getUTCSeconds()) + ' UTC';
  }
  function duration(sec) {
    var s = Math.abs(Math.round(sec));
    if (s < 60) return s + ' s';
    if (s < 3600) return Math.floor(s / 60) + ' min ' + (s % 60) + ' s';
    if (s < 86400) return Math.floor(s / 3600) + ' h ' + Math.floor((s % 3600) / 60) + ' min';
    if (s < 86400 * 365) return Math.floor(s / 86400) + ' days ' + Math.floor((s % 86400) / 3600) + ' h';
    return (s / (86400 * 365.25)).toFixed(1) + ' years';
  }
  function relative(sec, now) {
    var d = sec - now;
    if (Math.abs(d) < 1) return 'now';
    return d > 0 ? 'in ' + duration(d) : duration(d) + ' ago';
  }

  /* ------------------------------------------------------------------ *
   * Analysis: claims table and findings
   * ------------------------------------------------------------------ */
  function describeValue(name, value, now, isHeader) {
    if (!isHeader && TIME_CLAIMS[name] && typeof value === 'number' && isFinite(value)) {
      return isoUtc(value) + ' (' + relative(value, now) + ')';
    }
    if (name === 'scope' && typeof value === 'string') return value.split(/\s+/).length + ' scope(s): ' + value;
    return null;
  }

  function claimRows(obj, dict, now, isHeader) {
    var rows = [];
    if (!isPlainObject(obj)) return rows;
    for (var k in obj) {
      if (!Object.prototype.hasOwnProperty.call(obj, k)) continue;
      var d = dict[k];
      rows.push({
        name: k,
        value: obj[k],
        label: d ? d[0] : 'Custom',
        meaning: d ? d[1] : (isHeader ? 'Not a registered header parameter.' : 'Not a registered claim; its meaning is defined by the issuer.'),
        ref: d ? d[2] : '',
        detail: describeValue(k, obj[k], now, isHeader)
      });
    }
    return rows;
  }

  var PII_KEYS = /^(email|phone|phone_number|mobile|address|street|postal_code|birthdate|dob|ssn|national_id|passport|password|passwd|pwd|secret|api_key|apikey|credit_card|card_number|iban)$/i;

  function analyze(d, opts) {
    var now = opts && typeof opts.now === 'number' ? opts.now : Math.floor(Date.now() / 1000);
    var skew = opts && typeof opts.skew === 'number' ? opts.skew : 0;
    var f = [];
    var time = { state: 'none', label: 'No time claims' };
    function add(level, code, text) {
      f.push({ level: level, code: code, text: text });
    }
    var h = d.header || {};
    var p = isPlainObject(d.payload) ? d.payload : null;

    if (d.kind === 'JWE') {
      add('info', 'jwe', 'This is an encrypted token (JWE). Only the header can be read; the payload needs the recipient\'s private key, which this tool does not ask for.');
      if (h.alg && !JWE_ALGS.test(h.alg)) add('warning', 'jwe-alg', 'Header "alg" (' + h.alg + ') is not a registered JWE key management algorithm.');
      if (!h.enc) add('error', 'jwe-enc', 'An encrypted token must have an "enc" header parameter.');
      if (h.alg === 'RSA1_5') add('warning', 'rsa15', 'RSA1_5 key encryption is vulnerable to padding-oracle attacks; prefer RSA-OAEP-256 or ECDH-ES.');
      return { findings: f, time: time, rows: { header: claimRows(h, HEADER_PARAMS, now, true), payload: [] } };
    }

    // Algorithm
    if (!('alg' in h)) add('error', 'alg-missing', 'The header has no "alg". A signed JWT must say how it is signed.');
    else if (h.alg === 'none' || (typeof h.alg === 'string' && h.alg.toLowerCase() === 'none')) {
      add('danger', 'alg-none', 'alg is "' + h.alg + '": the token is unsigned, so anyone can create or change it. Services must reject it unless unsigned tokens are explicitly expected.');
      if (d.signature && d.signature.length) add('error', 'none-sig', 'An unsigned token must have an empty signature part, but this one has a signature.');
    } else if (!ALGS[h.alg]) {
      if (KNOWN_UNSUPPORTED[h.alg]) add('info', 'alg-unsupported', h.alg + ' is a registered algorithm, but ' + KNOWN_UNSUPPORTED[h.alg] + ', so this tool cannot verify it.');
      else add('warning', 'alg-unknown', '"' + h.alg + '" is not a registered JWS algorithm name. Names are case-sensitive.');
    } else {
      var a = ALGS[h.alg];
      if (a.family === 'HMAC') add('info', 'hmac', h.alg + ' uses one shared secret for signing and verifying, so every service that can check the token can also create one. Prefer an asymmetric algorithm when several services verify tokens.');
      if (h.alg === 'EdDSA') add('info', 'eddsa', '"EdDSA" is deprecated by RFC 9864 (2025). New tokens should use the fully specified name "Ed25519".');
    }
    // Header risks
    if (h.jku) add('warning', 'jku', 'Header contains "jku" (key set URL). Never fetch verification keys from a URL inside the token; use a key set you configured yourself.');
    if (h.x5u) add('warning', 'x5u', 'Header contains "x5u" (certificate URL). Never fetch certificates from a URL inside the token without a strict allowlist.');
    if (h.jwk) add('warning', 'jwk', 'Header embeds a public key ("jwk"). Verifying with a key the token carries proves nothing: an attacker can sign with their own key.');
    if (typeof h.kid === 'string' && /(\.\.|[\/\\'";|`$<>]|\u0000|\s)/.test(h.kid)) add('warning', 'kid', 'The "kid" contains characters such as ../, quotes or ; that are used in path-traversal and injection attacks against key lookups. Treat it as untrusted input.');
    if (h.kid !== undefined && typeof h.kid !== 'string') add('warning', 'kid-type', '"kid" should be a string.');
    if (h.crit !== undefined) {
      if (!Array.isArray(h.crit) || !h.crit.length) add('error', 'crit', '"crit" must be a non-empty array of header names.');
      else add('warning', 'crit', 'Header lists critical parameters (' + h.crit.join(', ') + '). A receiver that does not understand all of them must reject the token.');
    }
    if (h.zip !== undefined) add('warning', 'zip', '"zip" (compression) is only defined for encrypted tokens. Compressed signed tokens are rejected by most libraries.');
    if (h.b64 === false) add('info', 'b64', 'The payload is not base64url-encoded (RFC 7797). This tool shows it but cannot verify it.');
    if (d.duplicates.header.length) add('danger', 'dup-header', 'Duplicate header parameter(s): ' + d.duplicates.header.join(', ') + '. Libraries disagree on which value wins, which attackers can exploit. Reject such tokens.');
    if (d.padding.length) add('warning', 'padding', d.padding.join(' and ') + ' contain "=" padding. JWTs must use base64url without padding; strict libraries reject this.');
    if (d.nested) add('info', 'nested', 'cty is "JWT": the payload is another token. Decode it separately.');
    var total = d.segments.join('.').length;
    if (total > 8000) add('info', 'size', 'The token is ' + total + ' characters. Many servers limit request headers to about 8 KB.');

    if (!p) return { findings: f, time: time, rows: { header: claimRows(h, HEADER_PARAMS, now, true), payload: [] } };

    // Claims
    if (d.duplicates.payload.length) add('danger', 'dup-claims', 'Duplicate claim name(s): ' + d.duplicates.payload.join(', ') + '. RFC 7519 says such tokens must be rejected or use the last value; parsers disagree, so reject them.');
    var keys = Object.keys(TIME_CLAIMS);
    for (var i = 0; i < keys.length; i++) {
      var k = keys[i];
      if (!(k in p)) continue;
      var v = p[k];
      if (typeof v === 'string' && /^\d+$/.test(v)) add('warning', 'time-string', '"' + k + '" is a string ("' + v + '"). It must be a number of seconds; many libraries reject or misread strings.');
      else if (typeof v !== 'number' || !isFinite(v)) add('error', 'time-type', '"' + k + '" must be a number of seconds since 1970-01-01 UTC.');
      else if (v > 1e11) add('warning', 'time-ms', '"' + k + '" looks like milliseconds (' + v + '). JWT times are in seconds; read as seconds this is the year ' + Math.floor(1970 + v / 31557600) + '.');
    }
    var exp = typeof p.exp === 'number' ? p.exp : null;
    var nbf = typeof p.nbf === 'number' ? p.nbf : null;
    var iat = typeof p.iat === 'number' ? p.iat : null;
    if (exp !== null && now >= exp + skew) {
      time = { state: 'expired', label: 'Expired ' + duration(now - exp) + ' ago' };
      add('danger', 'expired', 'Expired: exp was ' + isoUtc(exp) + ', ' + duration(now - exp) + ' ago.');
    } else if (nbf !== null && now + skew < nbf) {
      time = { state: 'early', label: 'Not valid for another ' + duration(nbf - now) };
      add('danger', 'nbf', 'Not yet valid: nbf is ' + isoUtc(nbf) + ', ' + duration(nbf - now) + ' from now.');
    } else if (exp !== null) {
      time = { state: 'valid', label: 'Valid for another ' + duration(exp - now) };
    } else {
      time = { state: 'noexp', label: 'Never expires' };
    }
    if (exp === null) add('warning', 'no-exp', 'No "exp" claim: the token never expires. A stolen token stays usable until the signing key changes.');
    if (iat !== null && iat > now + skew) add('warning', 'iat-future', '"iat" is in the future (' + relative(iat, now) + '). The issuer\'s clock may be wrong.');
    if (exp !== null && nbf !== null && nbf >= exp) add('error', 'nbf-exp', '"nbf" is not before "exp", so the token can never be valid.');
    if (exp !== null && iat !== null && exp - iat > 86400) add('warning', 'lifetime', 'Long lifetime: ' + duration(exp - iat) + ' between iat and exp. Access tokens are usually valid for minutes to an hour.');
    if (exp !== null && iat !== null && exp <= iat) add('error', 'exp-iat', '"exp" is not after "iat".');
    if (!('aud' in p)) add('info', 'no-aud', 'No "aud" claim. Without an audience, a token for one service may be accepted by another.');
    else if (!(typeof p.aud === 'string' || (Array.isArray(p.aud) && p.aud.every(function (x) { return typeof x === 'string'; })))) add('error', 'aud-type', '"aud" must be a string or an array of strings.');
    if (!('iss' in p)) add('info', 'no-iss', 'No "iss" claim. Services cannot check who issued the token.');
    var looksAccess = 'scope' in p || 'client_id' in p;
    if (looksAccess && h.typ !== undefined && String(h.typ).toLowerCase() !== 'at+jwt' && String(h.typ).toLowerCase() !== 'application/at+jwt') add('info', 'typ', 'This looks like an OAuth access token (it has scope or client_id). RFC 9068 recommends typ "at+jwt" so it cannot be confused with an ID token.');
    var pii = [];
    for (var key in p) if (Object.prototype.hasOwnProperty.call(p, key) && PII_KEYS.test(key)) pii.push(key);
    if (pii.length) add('warning', 'pii', 'Readable personal or secret data: ' + pii.join(', ') + '. A JWT is encoded, not encrypted; anyone holding the token can read it.');
    if (!f.some(function (x) { return x.level === 'danger' || x.level === 'error' || x.level === 'warning'; })) add('ok', 'clean', 'No structural or claim problems found. The signature still needs checking below.');
    return { findings: f, time: time, rows: { header: claimRows(h, HEADER_PARAMS, now, true), payload: claimRows(p, CLAIMS, now, false) } };
  }

  /* ------------------------------------------------------------------ *
   * Minimal DER reader and writer (for PEM keys and certificates)
   * ------------------------------------------------------------------ */
  function derRead(bytes, pos) {
    if (pos + 2 > bytes.length) throw new Error('Truncated DER data');
    var tag = bytes[pos];
    var len = bytes[pos + 1];
    var hdr = 2;
    if (len & 0x80) {
      var n = len & 0x7f;
      if (n < 1 || n > 4) throw new Error('Unsupported DER length');
      len = 0;
      for (var i = 0; i < n; i++) len = (len * 256) + bytes[pos + 2 + i];
      hdr += n;
    }
    if (pos + hdr + len > bytes.length) throw new Error('Truncated DER data');
    return { tag: tag, start: pos, contentStart: pos + hdr, end: pos + hdr + len };
  }
  function derChildren(bytes, node) {
    var out = [];
    var p = node.contentStart;
    while (p < node.end) {
      var c = derRead(bytes, p);
      out.push(c);
      p = c.end;
    }
    return out;
  }
  function derOid(bytes, node) {
    var b = bytes.subarray(node.contentStart, node.end);
    var parts = [Math.floor(b[0] / 40), b[0] % 40];
    var v = 0;
    for (var i = 1; i < b.length; i++) {
      v = v * 128 + (b[i] & 0x7f);
      if (!(b[i] & 0x80)) {
        parts.push(v);
        v = 0;
      }
    }
    return parts.join('.');
  }
  function derLen(n) {
    if (n < 128) return new Uint8Array([n]);
    var out = [];
    while (n > 0) {
      out.unshift(n & 255);
      n = Math.floor(n / 256);
    }
    return new Uint8Array([0x80 | out.length].concat(out));
  }
  function derWrap(tag, content) {
    return concatBytes([new Uint8Array([tag]), derLen(content.length), content]);
  }

  var OIDS = {
    '1.2.840.113549.1.1.1': 'RSA',
    '1.2.840.10045.2.1': 'EC',
    '1.3.101.112': 'Ed25519',
    '1.3.101.113': 'Ed448',
    '1.2.840.10045.3.1.7': 'P-256',
    '1.3.132.0.34': 'P-384',
    '1.3.132.0.35': 'P-521',
    '1.3.132.0.10': 'secp256k1'
  };

  // Returns {type, curve} for an SPKI DER.
  function spkiInfo(der) {
    var root = derRead(der, 0);
    var kids = derChildren(der, root);
    var algId = derChildren(der, kids[0]);
    var type = OIDS[derOid(der, algId[0])] || 'unknown';
    var curve = null;
    if (type === 'EC' && algId[1] && algId[1].tag === 0x06) curve = OIDS[derOid(der, algId[1])] || 'unknown curve';
    if (type === 'Ed25519' || type === 'Ed448') {
      curve = type;
      type = 'OKP';
    }
    return { type: type, curve: curve };
  }

  function certToSpki(der) {
    var cert = derRead(der, 0);
    var tbs = derChildren(der, cert)[0];
    var f = derChildren(der, tbs);
    var idx = f[0].tag === 0xa0 ? 6 : 5; // version is optional
    var spki = f[idx];
    var validity = derChildren(der, f[idx - 2]);
    return { spki: der.slice(spki.start, spki.end), notAfter: derTime(der, validity[1]) };
  }
  function derTime(der, node) {
    var s = '';
    for (var i = node.contentStart; i < node.end; i++) s += String.fromCharCode(der[i]);
    var y;
    if (node.tag === 0x17) {
      y = parseInt(s.slice(0, 2), 10);
      y = y < 50 ? 2000 + y : 1900 + y;
      s = s.slice(2);
    } else {
      y = parseInt(s.slice(0, 4), 10);
      s = s.slice(4);
    }
    return Date.UTC(y, parseInt(s.slice(0, 2), 10) - 1, parseInt(s.slice(2, 4), 10), parseInt(s.slice(4, 6), 10), parseInt(s.slice(6, 8), 10), parseInt(s.slice(8, 10), 10)) / 1000;
  }

  function pkcs1ToSpki(pkcs1) {
    var algId = derWrap(0x30, concatBytes([new Uint8Array([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]), new Uint8Array([0x05, 0x00])]));
    var bitString = derWrap(0x03, concatBytes([new Uint8Array([0]), pkcs1]));
    return derWrap(0x30, concatBytes([algId, bitString]));
  }

  function pemBlocks(text) {
    var re = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g;
    var out = [];
    var m;
    while ((m = re.exec(text))) {
      var bytes = anyB64ToBytes(m[2]);
      out.push({ label: m[1], der: bytes });
    }
    return out;
  }

  /* ------------------------------------------------------------------ *
   * Key material parsing
   * ------------------------------------------------------------------ */
  function parseKeyMaterial(text) {
    var t = String(text || '').replace(/^\s+|\s+$/g, '');
    if (!t) return { kind: 'empty' };
    if (t.charAt(0) === '{') {
      var p = parseJson(t);
      if (p.error) return { kind: 'error', message: 'Key is not valid JSON (' + p.error + ', line ' + p.line + ').' };
      var v = p.value;
      if (isPlainObject(v) && Array.isArray(v.keys)) return { kind: 'jwks', keys: v.keys.filter(isPlainObject) };
      if (isPlainObject(v) && typeof v.kty === 'string') return { kind: 'jwk', jwk: v, isPrivate: 'd' in v || (v.kty === 'oct') };
      return { kind: 'error', message: 'JSON key must be a JWK (with "kty") or a JWK Set (with "keys").' };
    }
    var blocks = pemBlocks(t);
    if (!blocks.length) return { kind: 'error', message: 'Paste a PEM key (-----BEGIN PUBLIC KEY-----), a certificate, a JWK or a JWK Set.' };
    var b = blocks[0];
    if (!b.der) return { kind: 'error', message: 'The PEM block is not valid base64.' };
    try {
      if (b.label === 'PUBLIC KEY') return { kind: 'spki', der: b.der, info: spkiInfo(b.der) };
      if (b.label === 'RSA PUBLIC KEY') {
        var spki = pkcs1ToSpki(b.der);
        return { kind: 'spki', der: spki, info: { type: 'RSA', curve: null }, note: 'Converted the PKCS#1 RSA key to SubjectPublicKeyInfo.' };
      }
      if (b.label === 'CERTIFICATE') {
        var c = certToSpki(b.der);
        return { kind: 'spki', der: c.spki, info: spkiInfo(c.spki), certNotAfter: c.notAfter, note: 'Using the public key from the certificate. The certificate chain itself is not validated.' };
      }
      if (b.label === 'PRIVATE KEY') return { kind: 'pkcs8', der: b.der, isPrivate: true };
      if (b.label === 'RSA PRIVATE KEY' || b.label === 'EC PRIVATE KEY') return { kind: 'error', message: 'This is a traditional "' + b.label + '" file. Convert it to PKCS#8 first: openssl pkcs8 -topk8 -nocrypt -in key.pem' };
      if (b.label === 'ENCRYPTED PRIVATE KEY') return { kind: 'error', message: 'Encrypted private keys are not supported. Use the public key to verify.' };
    } catch (e) {
      return { kind: 'error', message: 'Could not read the ' + b.label + ': ' + e.message + '.' };
    }
    return { kind: 'error', message: 'Unsupported PEM type "' + b.label + '".' };
  }

  function importParams(alg) {
    var a = ALGS[alg];
    if (a.family === 'RSA') return { name: a.name, hash: a.hash };
    if (a.family === 'EC') return { name: 'ECDSA', namedCurve: a.curve };
    if (a.family === 'OKP') return { name: 'Ed25519' };
    return { name: 'HMAC', hash: a.hash };
  }
  function verifyParams(alg) {
    var a = ALGS[alg];
    if (a.family === 'RSA') return a.name === 'RSA-PSS' ? { name: 'RSA-PSS', saltLength: a.salt } : { name: a.name };
    if (a.family === 'EC') return { name: 'ECDSA', hash: a.hash };
    if (a.family === 'OKP') return { name: 'Ed25519' };
    return { name: 'HMAC' };
  }
  function familyOfJwk(jwk) {
    if (jwk.kty === 'RSA') return 'RSA';
    if (jwk.kty === 'EC') return 'EC';
    if (jwk.kty === 'OKP') return 'OKP';
    if (jwk.kty === 'oct') return 'HMAC';
    return 'unknown';
  }
  function publicJwk(jwk) {
    if (jwk.kty === 'RSA') return { kty: 'RSA', n: jwk.n, e: jwk.e };
    if (jwk.kty === 'EC') return { kty: 'EC', crv: jwk.crv, x: jwk.x, y: jwk.y };
    if (jwk.kty === 'OKP') return { kty: 'OKP', crv: jwk.crv, x: jwk.x };
    return null;
  }
  function mismatch(alg, family, curve) {
    var a = ALGS[alg];
    if (a.family !== family) return 'The token uses ' + alg + ' but the key is ' + (family === 'HMAC' ? 'a shared secret' : 'an ' + family + ' key') + '. A key may only be used with the algorithm family it was made for.';
    if (a.curve && curve && a.curve !== curve) return 'The token uses ' + alg + ' (curve ' + a.curve + ') but the key is on curve ' + curve + '.';
    return null;
  }

  // Resolves to a CryptoKey for verification, plus notes.
  function importVerifyKey(alg, material, kid) {
    var s = subtle();
    var a = ALGS[alg];
    var notes = [];
    if (material.kind === 'jwks') {
      var cands = material.keys.filter(function (k) {
        return familyOfJwk(k) === a.family && (!k.alg || k.alg === alg) && (!k.use || k.use === 'sig') && (!a.curve || !k.crv || k.crv === a.curve);
      });
      if (kid !== undefined) {
        var byKid = cands.filter(function (k) { return k.kid === kid; });
        if (!byKid.length) return Promise.reject(new Error('No key in the set has kid "' + kid + '" and matches ' + alg + '. Keys in the set: ' + (material.keys.map(function (k) { return k.kid || '(no kid)'; }).join(', ') || 'none') + '.'));
        cands = byKid;
        notes.push('Selected the key with kid "' + kid + '" from the key set.');
      } else if (cands.length > 1) {
        notes.push('The token has no kid, so each of the ' + cands.length + ' matching keys was tried.');
      }
      if (!cands.length) return Promise.reject(new Error('No key in the set matches ' + alg + '.'));
      return Promise.resolve({ multi: cands.map(function (k) { return { kind: 'jwk', jwk: k }; }), notes: notes });
    }
    if (material.kind === 'jwk') {
      var fam = familyOfJwk(material.jwk);
      var mm = mismatch(alg, fam, material.jwk.crv);
      if (mm) return Promise.reject(new Error(mm));
      if (material.jwk.alg && material.jwk.alg !== alg) return Promise.reject(new Error('The key is restricted to alg "' + material.jwk.alg + '" but the token uses ' + alg + '.'));
      if ('d' in material.jwk) notes.push('You pasted a private key. Only its public part was used. Never share private keys.');
      var pj = publicJwk(material.jwk);
      return s.importKey('jwk', pj, importParams(alg), true, ['verify']).then(function (k) { return { key: k, notes: notes }; });
    }
    if (material.kind === 'spki') {
      var mm2 = mismatch(alg, material.info.type, material.info.curve);
      if (mm2) return Promise.reject(new Error(mm2));
      if (material.note) notes.push(material.note);
      return s.importKey('spki', material.der, importParams(alg), true, ['verify']).then(function (k) { return { key: k, notes: notes }; });
    }
    if (material.kind === 'pkcs8') {
      notes.push('You pasted a private key. Only its public part was used. Never share private keys.');
      var sp = a.family === 'OKP' ? { name: 'Ed25519' } : importParams(alg);
      return s.importKey('pkcs8', material.der, sp, true, ['sign']).then(function (pk) {
        return s.exportKey('jwk', pk);
      }).then(function (jwk) {
        return s.importKey('jwk', publicJwk(jwk), importParams(alg), true, ['verify']);
      }).then(function (k) { return { key: k, notes: notes }; }, function () {
        throw new Error('This private key does not match ' + alg + '.');
      });
    }
    return Promise.reject(new Error(material.message || 'Unsupported key.'));
  }

  function rsaBits(key) {
    return subtle().exportKey('jwk', key).then(function (j) {
      var n = anyB64ToBytes(j.n);
      var bits = n.length * 8;
      for (var i = 0; i < 8 && n.length && !(n[0] & (0x80 >> i)); i++) bits--;
      return bits;
    });
  }

  function secretBytes(text, encoding) {
    if (encoding === 'base64url' || encoding === 'base64') {
      var b = anyB64ToBytes(text);
      if (!b) throw new Error('The secret is not valid ' + encoding + '.');
      return b;
    }
    return utf8Encode(text);
  }

  /*
   * verify(decoded, {mode: 'secret'|'key', secret, encoding, keyText}) ->
   *   Promise<{status: 'valid'|'invalid'|'error'|'skipped', message, notes, warnings}>
   */
  function verify(d, opts) {
    var res = { status: 'error', message: '', notes: [], warnings: [] };
    var s = subtle();
    if (!d || d.kind !== 'JWS' || !d.header) {
      res.status = 'skipped';
      res.message = d && d.kind === 'JWE' ? 'Encrypted tokens cannot be verified here.' : 'Decode a valid token first.';
      return Promise.resolve(res);
    }
    var alg = d.header.alg;
    if (alg === 'none') {
      res.status = 'invalid';
      res.message = 'Unsigned token (alg "none"): there is no signature to verify. Treat it as untrusted.';
      return Promise.resolve(res);
    }
    if (!ALGS[alg]) {
      res.message = KNOWN_UNSUPPORTED[alg] ? alg + ' cannot be verified in the browser: ' + KNOWN_UNSUPPORTED[alg] + '.' : 'Unknown algorithm "' + alg + '".';
      return Promise.resolve(res);
    }
    if (d.header.b64 === false) {
      res.message = 'Tokens with b64=false (RFC 7797) are not supported for verification.';
      return Promise.resolve(res);
    }
    if (d.header.crit) {
      res.status = 'invalid';
      res.message = 'The token lists critical header parameters (' + [].concat(d.header.crit).join(', ') + ') that this verifier does not implement, so RFC 7515 requires rejecting it.';
      return Promise.resolve(res);
    }
    if (!s) {
      res.message = 'This browser does not provide Web Crypto. Open the page over HTTPS in a current browser.';
      return Promise.resolve(res);
    }
    var a = ALGS[alg];
    var sig = d.signature;
    if (a.family === 'EC' && sig.length !== a.sigLen) {
      res.status = 'invalid';
      res.message = 'The ' + alg + ' signature is ' + sig.length + ' bytes; it must be ' + a.sigLen + '. ' + (sig[0] === 0x30 ? 'It looks DER-encoded, but JWS requires the raw R||S format (RFC 7518 §3.4).' : '');
      return Promise.resolve(res);
    }
    if (a.family === 'OKP' && sig.length !== 64) {
      res.status = 'invalid';
      res.message = 'An Ed25519 signature must be 64 bytes; this one is ' + sig.length + '.';
      return Promise.resolve(res);
    }

    if (a.family === 'HMAC') {
      if (opts.mode !== 'secret') {
        res.message = alg + ' is verified with a shared secret, not a public key. Choose "Secret".';
        return Promise.resolve(res);
      }
      var secretText = opts.secret || '';
      if (!secretText) {
        res.status = 'skipped';
        res.message = 'Enter the secret to check the signature.';
        return Promise.resolve(res);
      }
      var keyBytes;
      try {
        keyBytes = secretBytes(secretText, opts.encoding);
      } catch (e) {
        res.message = e.message;
        return Promise.resolve(res);
      }
      if (/-----BEGIN [A-Z ]*KEY-----|"kty"\s*:/.test(secretText)) res.warnings.push('The secret looks like a public key. If this token verifies, it was forged with the algorithm-confusion attack: the public key, which everyone knows, was used as an HMAC secret. Services must fix the expected algorithm and never let the token choose it.');
      if (keyBytes.length < a.size) res.warnings.push('The secret is ' + keyBytes.length + ' bytes; RFC 7518 §3.2 requires at least ' + a.size + ' bytes for ' + alg + '. Short secrets can be guessed offline from any token.');
      if (keyBytes.length < 64 && /^[a-z0-9 _-]{0,24}$/i.test(secretText) && opts.encoding === 'utf8') res.warnings.push('The secret looks like a short word or phrase. Use a random value of at least ' + a.size + ' bytes.');
      return s.importKey('raw', keyBytes, { name: 'HMAC', hash: a.hash }, false, ['verify']).then(function (k) {
        return s.verify({ name: 'HMAC' }, k, sig, d.signingInput);
      }).then(function (ok) {
        res.status = ok ? 'valid' : 'invalid';
        res.message = ok ? 'Signature verified with the secret.' : 'Invalid signature: the token was changed or signed with a different secret.';
        return res;
      }, function (e) {
        res.message = 'Could not verify: ' + e.message;
        return res;
      });
    }

    if (opts.mode !== 'key') {
      res.status = 'error';
      res.message = alg + ' is verified with a public key. Choose "Public key".';
      return Promise.resolve(res);
    }
    var material = opts.material || parseKeyMaterial(opts.keyText);
    if (material.kind === 'empty') {
      res.status = 'skipped';
      res.message = 'Paste the public key (PEM, certificate, JWK or JWK Set) to check the signature.';
      return Promise.resolve(res);
    }
    if (material.kind === 'error') {
      res.message = material.message;
      return Promise.resolve(res);
    }
    if (material.kind === 'jwk' && material.jwk.kty === 'oct') {
      res.message = 'This JWK is a shared secret (kty "oct"); ' + alg + ' needs a public key.';
      return Promise.resolve(res);
    }
    if (material.certNotAfter && material.certNotAfter * 1000 < Date.now()) res.warnings.push('The certificate expired on ' + isoUtc(material.certNotAfter) + '.');
    var params = verifyParams(alg);
    return importVerifyKey(alg, material, d.header.kid).then(function (imp) {
      res.notes = res.notes.concat(imp.notes);
      var list = imp.multi ? imp.multi : [null];
      var idx = 0;
      function next() {
        if (idx >= list.length) {
          res.status = 'invalid';
          res.message = 'Invalid signature: the token was changed or signed with a different key.';
          return res;
        }
        var item = list[idx++];
        var keyP = item ? s.importKey('jwk', publicJwk(item.jwk), importParams(alg), true, ['verify']) : Promise.resolve(imp.key);
        return keyP.then(function (key) {
          return s.verify(params, key, sig, d.signingInput).then(function (ok) {
            if (!ok) return next();
            res.status = 'valid';
            res.message = 'Signature verified with the ' + (a.family === 'OKP' ? 'Ed25519' : a.family) + ' public key' + (item && item.jwk.kid ? ' (kid "' + item.jwk.kid + '")' : '') + '.';
            if (a.family === 'RSA') {
              return rsaBits(key).then(function (bits) {
                if (bits < 2048) res.warnings.push('The RSA key is ' + bits + ' bits; RFC 7518 requires at least 2048.');
                return res;
              });
            }
            return res;
          });
        }, function () {
          return next();
        });
      }
      return next();
    }).then(null, function (e) {
      res.status = 'error';
      res.message = (e && e.message) || 'The key could not be used with ' + alg + '.';
      if (/not supported|Unrecognized|NotSupported/i.test(res.message) && a.family === 'OKP') res.message = 'This browser does not support Ed25519 in Web Crypto yet. Try a current Chrome, Edge, Firefox or Safari.';
      return res;
    });
  }

  /* ------------------------------------------------------------------ *
   * Signing (encoder) and key generation
   * ------------------------------------------------------------------ */
  function thumbprint(jwk) {
    var m;
    if (jwk.kty === 'RSA') m = '{"e":"' + jwk.e + '","kty":"RSA","n":"' + jwk.n + '"}';
    else if (jwk.kty === 'EC') m = '{"crv":"' + jwk.crv + '","kty":"EC","x":"' + jwk.x + '","y":"' + jwk.y + '"}';
    else if (jwk.kty === 'OKP') m = '{"crv":"' + jwk.crv + '","kty":"OKP","x":"' + jwk.x + '"}';
    else return Promise.reject(new Error('Unsupported key type'));
    return subtle().digest('SHA-256', utf8Encode(m)).then(function (h) {
      return bytesToB64url(new Uint8Array(h));
    });
  }

  function toPem(label, der) {
    var b = bytesToB64(der);
    var lines = [];
    for (var i = 0; i < b.length; i += 64) lines.push(b.slice(i, i + 64));
    return '-----BEGIN ' + label + '-----\n' + lines.join('\n') + '\n-----END ' + label + '-----';
  }

  // Generates a key pair for alg. Resolves {privateKey, publicPem, publicJwk, kid}.
  function generateKeyPair(alg) {
    var a = ALGS[alg];
    var s = subtle();
    var gen;
    if (a.family === 'RSA') gen = { name: a.name, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: a.hash };
    else if (a.family === 'EC') gen = { name: 'ECDSA', namedCurve: a.curve };
    else if (a.family === 'OKP') gen = { name: 'Ed25519' };
    else return Promise.reject(new Error(alg + ' uses a secret, not a key pair.'));
    var pair;
    return s.generateKey(gen, true, ['sign', 'verify']).then(function (p) {
      pair = p;
      return Promise.all([s.exportKey('spki', p.publicKey), s.exportKey('jwk', p.publicKey)]);
    }).then(function (r) {
      var jwk = publicJwk(r[1]);
      return thumbprint(jwk).then(function (kid) {
        jwk.kid = kid;
        jwk.use = 'sig';
        jwk.alg = alg;
        return { privateKey: pair.privateKey, publicPem: toPem('PUBLIC KEY', new Uint8Array(r[0])), publicJwk: jwk, kid: kid };
      });
    });
  }

  function importSigningKey(alg, text) {
    var a = ALGS[alg];
    var m = parseKeyMaterial(text);
    if (m.kind === 'pkcs8') return subtle().importKey('pkcs8', m.der, importParams(alg), false, ['sign']);
    if (m.kind === 'jwk' && 'd' in m.jwk) {
      var mm = mismatch(alg, familyOfJwk(m.jwk), m.jwk.crv);
      if (mm) return Promise.reject(new Error(mm));
      var j = {};
      for (var k in m.jwk) if (/^(kty|crv|x|y|d|n|e|p|q|dp|dq|qi)$/.test(k)) j[k] = m.jwk[k];
      return subtle().importKey('jwk', j, importParams(alg), false, ['sign']);
    }
    if (a.family !== 'HMAC' && (m.kind === 'spki' || m.kind === 'jwk')) return Promise.reject(new Error('That is a public key. Signing needs the private key (PKCS#8 PEM or a JWK with "d"), or generate a new key pair.'));
    return Promise.reject(new Error(m.message || 'Paste a PKCS#8 private key or a private JWK.'));
  }

  // sign(header, payload, {alg, secret, encoding, privateKey}) -> Promise<token>
  function sign(header, payload, opts) {
    var alg = opts.alg;
    var s = subtle();
    var h = {};
    h.alg = alg;
    for (var k in header) if (Object.prototype.hasOwnProperty.call(header, k) && k !== 'alg') h[k] = header[k];
    var input = bytesToB64url(utf8Encode(JSON.stringify(h))) + '.' + bytesToB64url(utf8Encode(JSON.stringify(payload)));
    var data = utf8Encode(input);
    if (alg === 'none') return Promise.resolve(input + '.');
    var a = ALGS[alg];
    if (!a) return Promise.reject(new Error('Unsupported algorithm ' + alg));
    var keyP;
    if (a.family === 'HMAC') {
      var kb;
      try {
        kb = secretBytes(opts.secret || '', opts.encoding);
      } catch (e) {
        return Promise.reject(e);
      }
      if (!kb.length) return Promise.reject(new Error('Enter a secret.'));
      keyP = s.importKey('raw', kb, { name: 'HMAC', hash: a.hash }, false, ['sign']);
    } else {
      keyP = opts.privateKey ? Promise.resolve(opts.privateKey) : Promise.reject(new Error('Generate a key pair or paste a private key.'));
    }
    return keyP.then(function (key) {
      return s.sign(verifyParams(alg), key, data);
    }).then(function (sig) {
      return input + '.' + bytesToB64url(new Uint8Array(sig));
    });
  }

  /* ------------------------------------------------------------------ *
   * Samples (created fresh in the browser, so times are always current)
   * ------------------------------------------------------------------ */
  function randomId() {
    var b = new Uint8Array(12);
    (window.crypto || crypto).getRandomValues(b);
    return bytesToB64url(b);
  }

  function makeSample(name) {
    var now = Math.floor(Date.now() / 1000);
    var base = { iss: 'https://auth.example.com/', sub: 'user_8f14e45f', aud: 'https://api.example.com', iat: now, nbf: now, exp: now + 900, jti: randomId() };
    var hs = { mode: 'secret', secret: DATASET_TEST_KEY, encoding: 'utf8' };
    function hsToken(header, payload) {
      return sign(header, payload, { alg: header.alg, secret: DATASET_TEST_KEY, encoding: 'utf8' }).then(function (t) {
        return { token: t, verify: hs };
      });
    }
    function asym(alg, header, payload, keyFormat) {
      return generateKeyPair(alg).then(function (kp) {
        header.kid = kp.kid;
        return sign(header, payload, { alg: alg, privateKey: kp.privateKey }).then(function (t) {
          return { token: t, verify: { mode: 'key', keyText: keyFormat === 'jwk' ? JSON.stringify({ keys: [kp.publicJwk] }, null, 2) : kp.publicPem } };
        });
      });
    }
    if (name === 'access') {
      return hsToken({ alg: 'HS256', typ: 'at+jwt' }, assign(base, { client_id: 'web-dashboard', scope: 'orders:read orders:write', roles: ['support'] }));
    }
    if (name === 'idtoken') {
      return asym('RS256', { alg: 'RS256', typ: 'JWT' }, assign(base, { aud: 'web-dashboard', azp: 'web-dashboard', nonce: randomId(), auth_time: now - 30, amr: ['pwd', 'otp'], name: 'Asha Rao', email: 'asha.rao@example.com', email_verified: true }), 'pem');
    }
    if (name === 'es256') {
      return asym('ES256', { alg: 'ES256', typ: 'JWT' }, assign(base, { scope: 'profile' }), 'jwk');
    }
    if (name === 'ed25519') {
      return asym('Ed25519', { alg: 'Ed25519', typ: 'JWT' }, base, 'jwk');
    }
    if (name === 'expired') {
      return hsToken({ alg: 'HS256', typ: 'JWT' }, assign(base, { iat: now - 7200, nbf: now - 7200, exp: now - 3600 }));
    }
    if (name === 'none') {
      return sign({ typ: 'JWT' }, assign(base, { role: 'admin' }), { alg: 'none' }).then(function (t) {
        return { token: t, verify: { mode: 'secret', secret: '', encoding: 'utf8' } };
      });
    }
    if (name === 'risky') {
      var p = { iss: 'https://auth.example.com/', sub: 'user_8f14e45f', iat: String(now), email: 'asha.rao@example.com', phone_number: '+91 90000 00000' };
      return hsToken({ alg: 'HS256', typ: 'JWT', kid: '../../../../dev/null', jku: 'https://attacker.example/keys.json' }, p);
    }
    return Promise.reject(new Error('Unknown sample'));
  }
  function assign(a, b) {
    var o = {};
    var k;
    for (k in a) if (Object.prototype.hasOwnProperty.call(a, k)) o[k] = a[k];
    for (k in b) if (Object.prototype.hasOwnProperty.call(b, k)) o[k] = b[k];
    return o;
  }

  /* ------------------------------------------------------------------ *
   * JWKS fetch (only after the user clicks, never automatic)
   * ------------------------------------------------------------------ */
  function fetchJson(url) {
    var ctrl = typeof AbortController !== 'undefined' ? new AbortController() : null;
    var timer = ctrl ? setTimeout(function () { ctrl.abort(); }, 10000) : null;
    return fetch(url, { method: 'GET', credentials: 'omit', referrerPolicy: 'no-referrer', cache: 'no-store', redirect: 'follow', mode: 'cors', signal: ctrl ? ctrl.signal : undefined }).then(function (r) {
      if (timer) clearTimeout(timer);
      if (!r.ok) throw new Error('The server answered HTTP ' + r.status + '.');
      return r.text();
    }).then(function (t) {
      if (t.length > 1000000) throw new Error('The response is too large to be a key set.');
      var p = parseJson(t);
      if (p.error) throw new Error('The response is not JSON.');
      return p.value;
    }, function (e) {
      if (timer) clearTimeout(timer);
      if (e && e.message && /HTTP|large|JSON/.test(e.message)) throw e;
      throw new Error('The request failed. The server may not allow requests from other websites (CORS), or it may be unreachable. Copy the key set into the box instead.');
    });
  }

  function resolveJwks(url) {
    var u;
    try {
      u = new URL(url);
    } catch (e) {
      return Promise.reject(new Error('Enter a full https:// URL.'));
    }
    if (u.protocol !== 'https:') return Promise.reject(new Error('Only https:// URLs are allowed.'));
    var path = u.pathname;
    if (/\/\.well-known\/openid-configuration$/.test(path) || !/\.json$|jwks|keys|certs/i.test(path)) {
      var disc = /\/\.well-known\/openid-configuration$/.test(path) ? u.href : u.href.replace(/\/+$/, '') + '/.well-known/openid-configuration';
      return fetchJson(disc).then(function (cfg) {
        if (!cfg || typeof cfg.jwks_uri !== 'string' || !/^https:\/\//.test(cfg.jwks_uri)) throw new Error('The discovery document has no https jwks_uri.');
        return fetchJson(cfg.jwks_uri).then(function (j) { return { jwks: j, from: cfg.jwks_uri }; });
      });
    }
    return fetchJson(u.href).then(function (j) { return { jwks: j, from: u.href }; });
  }

  /* ------------------------------------------------------------------ *
   * DOM helpers (text only)
   * ------------------------------------------------------------------ */
  function el(tag, attrs, children) {
    var e = document.createElement(tag);
    if (attrs) {
      for (var k in attrs) {
        if (!Object.prototype.hasOwnProperty.call(attrs, k)) continue;
        if (k === 'text') e.textContent = attrs[k];
        else if (k === 'className') e.className = attrs[k];
        else e.setAttribute(k, attrs[k]);
      }
    }
    if (children) for (var i = 0; i < children.length; i++) if (children[i]) e.appendChild(typeof children[i] === 'string' ? document.createTextNode(children[i]) : children[i]);
    return e;
  }
  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  // Pretty JSON as DOM nodes with token classes.
  function jsonNodes(value, indent) {
    var frag = document.createDocumentFragment();
    function span(cls, text) {
      frag.appendChild(el('span', { className: cls, text: text }));
    }
    function walk(v, ind) {
      var pad = new Array(ind + 1).join('  ');
      if (v === null) span('jwt-lit', 'null');
      else if (typeof v === 'boolean') span('jwt-lit', String(v));
      else if (typeof v === 'number') span('jwt-num', JSON.stringify(v));
      else if (typeof v === 'string') span('jwt-str', JSON.stringify(v));
      else if (Array.isArray(v)) {
        if (!v.length) { span('jwt-pun', '[]'); return; }
        span('jwt-pun', '[');
        for (var i = 0; i < v.length; i++) {
          frag.appendChild(document.createTextNode('\n' + pad + '  '));
          walk(v[i], ind + 1);
          if (i < v.length - 1) span('jwt-pun', ',');
        }
        frag.appendChild(document.createTextNode('\n' + pad));
        span('jwt-pun', ']');
      } else {
        var keys = Object.keys(v);
        if (!keys.length) { span('jwt-pun', '{}'); return; }
        span('jwt-pun', '{');
        for (var j = 0; j < keys.length; j++) {
          frag.appendChild(document.createTextNode('\n' + pad + '  '));
          span('jwt-key', JSON.stringify(keys[j]));
          span('jwt-pun', ': ');
          walk(v[keys[j]], ind + 1);
          if (j < keys.length - 1) span('jwt-pun', ',');
        }
        frag.appendChild(document.createTextNode('\n' + pad));
        span('jwt-pun', '}');
      }
    }
    walk(value, indent || 0);
    return frag;
  }

  function copyText(text, btn) {
    function done(ok) {
      var old = btn.getAttribute('data-label') || btn.textContent;
      btn.setAttribute('data-label', old);
      btn.textContent = ok ? 'Copied' : 'Copy failed';
      setTimeout(function () { btn.textContent = old; }, 1500);
    }
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(function () { done(true); }, function () { done(false); });
    } else {
      var ta = el('textarea', { 'aria-hidden': 'true' });
      ta.value = text;
      ta.className = 'jwt-offscreen';
      document.body.appendChild(ta);
      ta.select();
      var ok = false;
      try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
      document.body.removeChild(ta);
      done(ok);
    }
  }

  function field(attrs) {
    var t = el('textarea', attrs);
    t.setAttribute('spellcheck', 'false');
    t.setAttribute('autocomplete', 'off');
    t.setAttribute('autocorrect', 'off');
    t.setAttribute('autocapitalize', 'off');
    t.setAttribute('data-gramm', 'false');
    t.setAttribute('data-lt-active', 'false');
    return t;
  }

  /* ------------------------------------------------------------------ *
   * App
   * ------------------------------------------------------------------ */
  function App(root) {
    this.root = root;
    this.uid = 'jwt' + Math.floor(Math.random() * 1e9);
    this.decoded = null;
    this.verifySeq = 0;
    this.encKey = null;
    this.build();
  }

  App.prototype.build = function () {
    var self = this;
    var id = function (s) { return self.uid + '-' + s; };
    clear(this.root);

    // Tabs
    var tabs = el('div', { className: 'jwt-tabs', role: 'tablist', 'aria-label': 'JWT tool mode' });
    this.tabDecode = el('button', { type: 'button', role: 'tab', id: id('tab-dec'), 'aria-selected': 'true', 'aria-controls': id('pane-dec'), className: 'jwt-tab', text: 'Decode & verify' });
    this.tabEncode = el('button', { type: 'button', role: 'tab', id: id('tab-enc'), 'aria-selected': 'false', 'aria-controls': id('pane-enc'), className: 'jwt-tab', tabindex: '-1', text: 'Create a test token' });
    tabs.appendChild(this.tabDecode);
    tabs.appendChild(this.tabEncode);
    this.root.appendChild(tabs);
    this.paneDec = el('div', { role: 'tabpanel', id: id('pane-dec'), 'aria-labelledby': id('tab-dec'), className: 'jwt-pane' });
    this.paneEnc = el('div', { role: 'tabpanel', id: id('pane-enc'), 'aria-labelledby': id('tab-enc'), className: 'jwt-pane', hidden: 'hidden' });
    this.root.appendChild(this.paneDec);
    this.root.appendChild(this.paneEnc);
    function selectTab(dec) {
      self.tabDecode.setAttribute('aria-selected', dec ? 'true' : 'false');
      self.tabEncode.setAttribute('aria-selected', dec ? 'false' : 'true');
      self.tabDecode.setAttribute('tabindex', dec ? '0' : '-1');
      self.tabEncode.setAttribute('tabindex', dec ? '-1' : '0');
      if (dec) { self.paneDec.removeAttribute('hidden'); self.paneEnc.setAttribute('hidden', 'hidden'); }
      else { self.paneEnc.removeAttribute('hidden'); self.paneDec.setAttribute('hidden', 'hidden'); }
    }
    this.tabDecode.addEventListener('click', function () { selectTab(true); });
    this.tabEncode.addEventListener('click', function () { selectTab(false); });
    tabs.addEventListener('keydown', function (e) {
      if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
        var dec = self.tabDecode.getAttribute('aria-selected') !== 'true';
        selectTab(dec);
        (dec ? self.tabDecode : self.tabEncode).focus();
        e.preventDefault();
      }
    });

    // ---------- Decode pane
    var P = this.paneDec;
    var privacy = el('p', { className: 'jwt-privacy', text: 'Runs entirely in your browser: the token and keys are never sent or stored. Still, do not paste live production tokens; use test tokens or tokens you can revoke.' });
    P.appendChild(privacy);

    var bar = el('div', { className: 'jwt-toolbar' });
    this.sampleSel = el('select', { id: id('sample'), className: 'jwt-select' });
    var samples = [['', 'Load a sample token...'], ['access', 'HS256 access token (RFC 9068)'], ['idtoken', 'RS256 OpenID Connect ID token'], ['es256', 'ES256 token with a JWK Set'], ['ed25519', 'Ed25519 token'], ['expired', 'Expired token'], ['none', 'Unsigned token (alg "none")'], ['risky', 'Token with risky header and claims']];
    for (var i = 0; i < samples.length; i++) this.sampleSel.appendChild(el('option', { value: samples[i][0], text: samples[i][1] }));
    bar.appendChild(el('label', { 'for': id('sample'), className: 'jwt-visually-hidden', text: 'Sample token' }));
    bar.appendChild(this.sampleSel);
    this.btnClear = el('button', { type: 'button', className: 'jwt-btn', text: 'Clear' });
    bar.appendChild(this.btnClear);
    P.appendChild(bar);

    P.appendChild(el('label', { 'for': id('token'), className: 'jwt-label', text: 'Encoded token (JWT)' }));
    this.input = field({ id: id('token'), className: 'jwt-input', rows: '5', placeholder: 'Paste a JWT, or a full "Authorization: Bearer ..." header' });
    P.appendChild(this.input);
    this.colored = el('div', { className: 'jwt-colored', 'aria-hidden': 'true' });
    P.appendChild(this.colored);
    this.notes = el('ul', { className: 'jwt-notes' });
    P.appendChild(this.notes);

    this.status = el('div', { className: 'jwt-status', role: 'status', 'aria-live': 'polite' });
    P.appendChild(this.status);

    var grid = el('div', { className: 'jwt-grid' });
    this.headerBox = this.panel(grid, 'Header', 'jwt-part-h');
    this.payloadBox = this.panel(grid, 'Payload', 'jwt-part-p');
    P.appendChild(grid);

    // Verify panel
    var v = el('section', { className: 'jwt-section', 'aria-labelledby': id('ver-title') });
    v.appendChild(el('h3', { id: id('ver-title'), className: 'jwt-h3', text: 'Verify signature' }));
    var modes = el('div', { className: 'jwt-modes', role: 'radiogroup', 'aria-label': 'Key type' });
    this.modeSecret = el('input', { type: 'radio', name: id('mode'), id: id('m-secret'), value: 'secret', checked: 'checked' });
    this.modeKey = el('input', { type: 'radio', name: id('mode'), id: id('m-key'), value: 'key' });
    modes.appendChild(el('label', { 'for': id('m-secret'), className: 'jwt-radio' }, [this.modeSecret, ' Secret (HS256/384/512)']));
    modes.appendChild(el('label', { 'for': id('m-key'), className: 'jwt-radio' }, [this.modeKey, ' Public key (RS, PS, ES, Ed25519)']));
    v.appendChild(modes);

    this.secretWrap = el('div', { className: 'jwt-secret' });
    this.secretWrap.appendChild(el('label', { 'for': id('secret'), className: 'jwt-label', text: 'Secret' }));
    this.secret = el('input', { type: 'password', id: id('secret'), className: 'jwt-text', autocomplete: 'off', spellcheck: 'false' });
    this.secret.setAttribute('data-1p-ignore', 'true');
    this.secret.setAttribute('data-lpignore', 'true');
    this.secretWrap.appendChild(this.secret);
    var sr = el('div', { className: 'jwt-row' });
    this.showSecret = el('input', { type: 'checkbox', id: id('show') });
    sr.appendChild(el('label', { 'for': id('show'), className: 'jwt-check' }, [this.showSecret, ' Show']));
    this.encoding = el('select', { id: id('enc'), className: 'jwt-select' });
    this.encoding.appendChild(el('option', { value: 'utf8', text: 'Text (UTF-8)' }));
    this.encoding.appendChild(el('option', { value: 'base64url', text: 'base64url' }));
    this.encoding.appendChild(el('option', { value: 'base64', text: 'base64' }));
    sr.appendChild(el('label', { 'for': id('enc'), className: 'jwt-inline-label', text: 'Secret format' }));
    sr.appendChild(this.encoding);
    this.secretWrap.appendChild(sr);
    v.appendChild(this.secretWrap);

    this.keyWrap = el('div', { className: 'jwt-key', hidden: 'hidden' });
    this.keyWrap.appendChild(el('label', { 'for': id('key'), className: 'jwt-label', text: 'Public key: PEM, X.509 certificate, JWK or JWK Set' }));
    this.keyText = field({ id: id('key'), className: 'jwt-input jwt-input-key', rows: '6', placeholder: '-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----' });
    this.keyWrap.appendChild(this.keyText);
    var fr = el('div', { className: 'jwt-row' });
    this.jwksUrl = el('input', { type: 'url', id: id('jwks'), className: 'jwt-text', placeholder: 'https://issuer.example.com/  or  .../jwks.json' });
    fr.appendChild(el('label', { 'for': id('jwks'), className: 'jwt-inline-label', text: 'Issuer or JWKS URL' }));
    fr.appendChild(this.jwksUrl);
    this.btnFetch = el('button', { type: 'button', className: 'jwt-btn', text: 'Fetch keys' });
    fr.appendChild(this.btnFetch);
    this.keyWrap.appendChild(fr);
    this.keyWrap.appendChild(el('p', { className: 'jwt-hint', text: 'Fetch keys asks your browser to request the issuer\'s public key set. Only the URL is requested; the token is never sent. Keys are never fetched from URLs inside the token.' }));
    v.appendChild(this.keyWrap);
    this.verifyOut = el('div', { className: 'jwt-verify', role: 'status', 'aria-live': 'polite' });
    v.appendChild(this.verifyOut);
    P.appendChild(v);

    // Time settings
    var t = el('section', { className: 'jwt-section jwt-time', 'aria-labelledby': id('time-title') });
    t.appendChild(el('h3', { id: id('time-title'), className: 'jwt-h3', text: 'Time checks' }));
    var tr = el('div', { className: 'jwt-row' });
    this.atInput = el('input', { type: 'text', id: id('at'), className: 'jwt-text jwt-short', placeholder: 'now' });
    tr.appendChild(el('label', { 'for': id('at'), className: 'jwt-inline-label', text: 'Check at (ISO date or Unix seconds)' }));
    tr.appendChild(this.atInput);
    this.skewInput = el('input', { type: 'number', id: id('skew'), className: 'jwt-text jwt-num-in', min: '0', max: '3600', value: '0' });
    tr.appendChild(el('label', { 'for': id('skew'), className: 'jwt-inline-label', text: 'Clock tolerance (s)' }));
    tr.appendChild(this.skewInput);
    t.appendChild(tr);
    P.appendChild(t);

    // Findings and claims
    var fsec = el('section', { className: 'jwt-section', 'aria-labelledby': id('find-title') });
    fsec.appendChild(el('h3', { id: id('find-title'), className: 'jwt-h3', text: 'Security and validity checks' }));
    this.findings = el('ul', { className: 'jwt-findings' });
    fsec.appendChild(this.findings);
    P.appendChild(fsec);
    var csec = el('section', { className: 'jwt-section', 'aria-labelledby': id('claims-title') });
    csec.appendChild(el('h3', { id: id('claims-title'), className: 'jwt-h3', text: 'Claims explained' }));
    this.claims = el('div', { className: 'jwt-claims' });
    csec.appendChild(this.claims);
    P.appendChild(csec);

    // ---------- Encode pane
    this.buildEncoder(id);

    // Events
    var timer = null;
    this.input.addEventListener('input', function () {
      clearTimeout(timer);
      timer = setTimeout(function () { self.run(); }, 120);
    });
    this.btnClear.addEventListener('click', function () {
      self.input.value = '';
      self.secret.value = '';
      self.keyText.value = '';
      self.sampleSel.value = '';
      self.run();
      self.input.focus();
    });
    this.sampleSel.addEventListener('change', function () {
      var name = self.sampleSel.value;
      if (!name) return;
      makeSample(name).then(function (s) {
        self.input.value = s.token;
        if (s.verify.mode === 'secret') {
          self.modeSecret.checked = true;
          self.secret.value = s.verify.secret;
          self.encoding.value = s.verify.encoding;
        } else {
          self.modeKey.checked = true;
          self.keyText.value = s.verify.keyText;
        }
        self.syncMode();
        self.run();
      }, function (e) {
        self.setStatus('error', name === 'ed25519' ? 'This browser cannot create Ed25519 keys yet.' : e.message);
      });
    });
    var vt = null;
    function reverify() {
      clearTimeout(vt);
      vt = setTimeout(function () { self.runVerify(); }, 200);
    }
    this.secret.addEventListener('input', reverify);
    this.keyText.addEventListener('input', reverify);
    this.encoding.addEventListener('change', reverify);
    this.modeSecret.addEventListener('change', function () { self.syncMode(); reverify(); });
    this.modeKey.addEventListener('change', function () { self.syncMode(); reverify(); });
    this.showSecret.addEventListener('change', function () { self.secret.type = self.showSecret.checked ? 'text' : 'password'; });
    this.atInput.addEventListener('input', function () { self.run(); });
    this.skewInput.addEventListener('input', function () { self.run(); });
    this.btnFetch.addEventListener('click', function () { self.fetchKeys(); });
    this.run();
  };

  App.prototype.panel = function (parent, title, cls) {
    var self = this;
    var box = el('section', { className: 'jwt-panel ' + cls });
    var head = el('div', { className: 'jwt-panel-head' });
    head.appendChild(el('h3', { className: 'jwt-panel-title', text: title }));
    var btn = el('button', { type: 'button', className: 'jwt-btn jwt-btn-sm', text: 'Copy' });
    head.appendChild(btn);
    box.appendChild(head);
    var pre = el('pre', { className: 'jwt-json', tabindex: '0' });
    box.appendChild(pre);
    parent.appendChild(box);
    btn.addEventListener('click', function () { copyText(pre.textContent, btn); });
    return pre;
  };

  App.prototype.syncMode = function () {
    var key = this.modeKey.checked;
    if (key) { this.keyWrap.removeAttribute('hidden'); this.secretWrap.setAttribute('hidden', 'hidden'); }
    else { this.secretWrap.removeAttribute('hidden'); this.keyWrap.setAttribute('hidden', 'hidden'); }
  };

  App.prototype.setStatus = function (state, text) {
    clear(this.status);
    this.status.className = 'jwt-status jwt-status-' + state;
    this.status.appendChild(document.createTextNode(text));
  };

  App.prototype.evalTime = function () {
    var raw = (this.atInput.value || '').replace(/^\s+|\s+$/g, '');
    var now = Math.floor(Date.now() / 1000);
    if (raw) {
      if (/^\d{9,11}$/.test(raw)) now = parseInt(raw, 10);
      else {
        var t = Date.parse(raw);
        if (!isNaN(t)) now = Math.floor(t / 1000);
      }
    }
    var skew = parseInt(this.skewInput.value, 10);
    return { now: now, skew: isNaN(skew) || skew < 0 ? 0 : Math.min(skew, 3600) };
  };

  App.prototype.run = function () {
    var n = normalizeToken(this.input.value);
    clear(this.notes);
    clear(this.colored);
    clear(this.headerBox);
    clear(this.payloadBox);
    clear(this.findings);
    clear(this.claims);
    clear(this.verifyOut);
    this.decoded = null;
    if (n.error) {
      this.setStatus('error', n.error);
      return;
    }
    for (var i = 0; i < n.notes.length; i++) this.notes.appendChild(el('li', { text: n.notes[i] }));
    if (!n.token) {
      this.setStatus('empty', 'Paste a token, or load a sample.');
      return;
    }
    var d = decode(n.token);
    this.decoded = d;
    // coloured token
    var cls = ['jwt-part-h', 'jwt-part-p', 'jwt-part-s', 'jwt-part-x', 'jwt-part-x'];
    for (var j = 0; j < d.segments.length; j++) {
      if (j) this.colored.appendChild(el('span', { className: 'jwt-dot', text: '.' }));
      this.colored.appendChild(el('span', { className: cls[j] || 'jwt-part-x', text: d.segments[j] }));
    }
    if (d.header) this.headerBox.appendChild(jsonNodes(d.header));
    else if (d.headerText) this.headerBox.textContent = d.headerText;
    if (d.kind === 'JWE') this.payloadBox.textContent = 'Encrypted. The payload of a JWE cannot be read without the recipient\'s private key.';
    else if (d.payload !== null && d.payload !== undefined) this.payloadBox.appendChild(jsonNodes(d.payload));
    else if (d.payloadText !== null) this.payloadBox.textContent = d.payloadText;

    var t = this.evalTime();
    var a = d.header ? analyze(d, t) : { findings: [], time: { state: 'none' }, rows: { header: [], payload: [] } };
    for (var e = 0; e < d.errors.length; e++) a.findings.unshift({ level: 'error', code: 'decode', text: d.errors[e] });
    var order = { danger: 0, error: 1, warning: 2, info: 3, ok: 4 };
    a.findings.sort(function (x, y) { return order[x.level] - order[y.level]; });
    var labels = { danger: 'Critical', error: 'Error', warning: 'Warning', info: 'Note', ok: 'OK' };
    for (var f = 0; f < a.findings.length; f++) {
      var it = a.findings[f];
      this.findings.appendChild(el('li', { className: 'jwt-finding jwt-' + it.level }, [el('strong', { text: labels[it.level] + ': ' }), it.text]));
    }
    this.renderClaims(a.rows);
    if (d.errors.length && !d.header) this.setStatus('error', 'Not a valid JWT: ' + d.errors[0]);
    else if (d.errors.length) this.setStatus('error', 'Decoded with problems. See the checks below.');
    else {
      var kind = d.kind === 'JWE' ? 'Encrypted JWT (JWE)' : (d.header.alg === 'none' ? 'Unsigned JWT' : 'Signed JWT (' + d.header.alg + ')');
      var st = a.time.state === 'expired' || a.time.state === 'early' ? 'error' : (a.time.state === 'valid' ? 'ok' : 'warn');
      this.setStatus(st, kind + '. ' + a.time.label + '.');
    }
    this.runVerify();
  };

  App.prototype.renderClaims = function (rows) {
    var self = this;
    function table(title, list) {
      if (!list.length) return;
      var tbl = el('table', { className: 'jwt-table' });
      tbl.appendChild(el('caption', { text: title }));
      var thead = el('thead');
      thead.appendChild(el('tr', null, [el('th', { scope: 'col', text: 'Name' }), el('th', { scope: 'col', text: 'Value' }), el('th', { scope: 'col', text: 'Meaning' })]));
      tbl.appendChild(thead);
      var tb = el('tbody');
      for (var i = 0; i < list.length; i++) {
        var r = list[i];
        var val = typeof r.value === 'string' ? r.value : JSON.stringify(r.value);
        var vcell = el('td', null, [el('code', { text: val })]);
        if (r.detail) vcell.appendChild(el('div', { className: 'jwt-detail', text: r.detail }));
        var mcell = el('td', null, [el('strong', { text: r.label }), ' ', r.meaning]);
        if (r.ref) mcell.appendChild(el('span', { className: 'jwt-ref', text: ' ' + r.ref }));
        tb.appendChild(el('tr', null, [el('th', { scope: 'row' }, [el('code', { text: r.name })]), vcell, mcell]));
      }
      tbl.appendChild(tb);
      self.claims.appendChild(el('div', { className: 'jwt-table-wrap' }, [tbl]));
    }
    table('Header parameters', rows.header);
    table('Payload claims', rows.payload);
  };

  App.prototype.runVerify = function () {
    var self = this;
    var seq = ++this.verifySeq;
    var d = this.decoded;
    if (!d || !d.header) { clear(this.verifyOut); return; }
    if (d.header.alg && ALGS[d.header.alg]) {
      var wantKey = ALGS[d.header.alg].family !== 'HMAC';
      if (wantKey !== this.modeKey.checked && !this.secret.value && !this.keyText.value) {
        (wantKey ? this.modeKey : this.modeSecret).checked = true;
        this.syncMode();
      }
    }
    verify(d, { mode: this.modeKey.checked ? 'key' : 'secret', secret: this.secret.value, encoding: this.encoding.value, keyText: this.keyText.value }).then(function (r) {
      if (seq !== self.verifySeq) return;
      clear(self.verifyOut);
      var cls = r.status === 'valid' ? 'ok' : (r.status === 'skipped' ? 'muted' : 'error');
      self.verifyOut.className = 'jwt-verify jwt-verify-' + cls;
      var label = r.status === 'valid' ? 'Signature verified' : r.status === 'invalid' ? 'Invalid signature' : r.status === 'skipped' ? 'Not checked' : 'Cannot verify';
      self.verifyOut.appendChild(el('p', null, [el('strong', { text: label + '. ' }), r.message]));
      var extra = r.notes.concat(r.warnings);
      if (extra.length) {
        var ul = el('ul', { className: 'jwt-notes' });
        for (var i = 0; i < r.notes.length; i++) ul.appendChild(el('li', { text: r.notes[i] }));
        for (var j = 0; j < r.warnings.length; j++) ul.appendChild(el('li', { className: 'jwt-warning-text', text: r.warnings[j] }));
        self.verifyOut.appendChild(ul);
      }
      if (r.status === 'valid') self.verifyOut.appendChild(el('p', { className: 'jwt-hint', text: 'A valid signature only proves who signed the token. Your service must still check iss, aud, exp and the algorithm it expects.' }));
    });
  };

  App.prototype.fetchKeys = function () {
    var self = this;
    var url = this.jwksUrl.value.replace(/^\s+|\s+$/g, '');
    if (!url && this.decoded && this.decoded.payload && typeof this.decoded.payload.iss === 'string' && /^https:\/\//.test(this.decoded.payload.iss)) {
      url = this.decoded.payload.iss;
      this.jwksUrl.value = url;
    }
    if (!url) {
      this.verifyOut.textContent = 'Enter the issuer URL or the JWKS URL first.';
      return;
    }
    this.btnFetch.disabled = true;
    this.btnFetch.textContent = 'Fetching...';
    resolveJwks(url).then(function (r) {
      self.keyText.value = JSON.stringify(r.jwks, null, 2);
      self.btnFetch.disabled = false;
      self.btnFetch.textContent = 'Fetch keys';
      self.runVerify();
    }, function (e) {
      self.btnFetch.disabled = false;
      self.btnFetch.textContent = 'Fetch keys';
      clear(self.verifyOut);
      self.verifyOut.className = 'jwt-verify jwt-verify-error';
      self.verifyOut.appendChild(el('p', null, [el('strong', { text: 'Could not fetch keys. ' }), e.message]));
    });
  };

  App.prototype.buildEncoder = function (id) {
    var self = this;
    var P = this.paneEnc;
    P.appendChild(el('p', { className: 'jwt-privacy', text: 'Create tokens for testing. Keys are generated and used only in this browser tab and disappear when you leave the page.' }));
    var r1 = el('div', { className: 'jwt-row' });
    this.encAlg = el('select', { id: id('e-alg'), className: 'jwt-select' });
    var algs = ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'Ed25519'];
    for (var i = 0; i < algs.length; i++) this.encAlg.appendChild(el('option', { value: algs[i], text: algs[i] }));
    r1.appendChild(el('label', { 'for': id('e-alg'), className: 'jwt-inline-label', text: 'Algorithm' }));
    r1.appendChild(this.encAlg);
    P.appendChild(r1);
    P.appendChild(el('label', { 'for': id('e-head'), className: 'jwt-label', text: 'Header (alg is set from the menu)' }));
    this.encHeader = field({ id: id('e-head'), className: 'jwt-input', rows: '3' });
    this.encHeader.value = '{\n  "typ": "JWT"\n}';
    P.appendChild(this.encHeader);
    P.appendChild(el('label', { 'for': id('e-pay'), className: 'jwt-label', text: 'Payload' }));
    this.encPayload = field({ id: id('e-pay'), className: 'jwt-input', rows: '9' });
    P.appendChild(this.encPayload);
    var r2 = el('div', { className: 'jwt-row' });
    var bTimes = el('button', { type: 'button', className: 'jwt-btn', text: 'Set iat, nbf and exp (+15 min)' });
    r2.appendChild(bTimes);
    P.appendChild(r2);

    this.encSecretWrap = el('div');
    this.encSecretWrap.appendChild(el('label', { 'for': id('e-sec'), className: 'jwt-label', text: 'Secret (at least 32 bytes for HS256)' }));
    this.encSecret = el('input', { type: 'text', id: id('e-sec'), className: 'jwt-text', autocomplete: 'off', spellcheck: 'false' });
    this.encSecret.setAttribute('data-1p-ignore', 'true');
    this.encSecretWrap.appendChild(this.encSecret);
    var bRand = el('button', { type: 'button', className: 'jwt-btn', text: 'Random secret' });
    this.encSecretWrap.appendChild(bRand);
    P.appendChild(this.encSecretWrap);

    this.encKeyWrap = el('div', { hidden: 'hidden' });
    var bGen = el('button', { type: 'button', className: 'jwt-btn jwt-btn-primary', text: 'Generate a key pair' });
    this.encKeyWrap.appendChild(bGen);
    this.encKeyWrap.appendChild(el('label', { 'for': id('e-priv'), className: 'jwt-label', text: 'Or paste a private key (PKCS#8 PEM or private JWK) for test keys only' }));
    this.encPriv = field({ id: id('e-priv'), className: 'jwt-input jwt-input-key', rows: '4' });
    this.encKeyWrap.appendChild(this.encPriv);
    P.appendChild(this.encKeyWrap);

    var bSign = el('button', { type: 'button', className: 'jwt-btn jwt-btn-primary', text: 'Create token' });
    P.appendChild(el('div', { className: 'jwt-row' }, [bSign]));
    this.encOut = el('div', { className: 'jwt-enc-out', role: 'status', 'aria-live': 'polite' });
    P.appendChild(this.encOut);

    function setTimes() {
      var p = parseJson(self.encPayload.value || '{}');
      var o = p.error || !isPlainObject(p.value) ? {} : p.value;
      var now = Math.floor(Date.now() / 1000);
      o.iat = now;
      o.nbf = now;
      o.exp = now + 900;
      self.encPayload.value = JSON.stringify(o, null, 2);
    }
    this.encPayload.value = JSON.stringify({ iss: 'https://auth.example.com/', sub: 'user_123', aud: 'https://api.example.com' }, null, 2);
    setTimes();
    bTimes.addEventListener('click', setTimes);
    bRand.addEventListener('click', function () {
      var b = new Uint8Array(32);
      window.crypto.getRandomValues(b);
      self.encSecret.value = bytesToB64url(b);
    });
    function syncAlg() {
      var fam = ALGS[self.encAlg.value].family;
      if (fam === 'HMAC') { self.encSecretWrap.removeAttribute('hidden'); self.encKeyWrap.setAttribute('hidden', 'hidden'); }
      else { self.encKeyWrap.removeAttribute('hidden'); self.encSecretWrap.setAttribute('hidden', 'hidden'); }
      self.encKey = null;
    }
    this.encAlg.addEventListener('change', syncAlg);
    bGen.addEventListener('click', function () {
      var alg = self.encAlg.value;
      bGen.disabled = true;
      generateKeyPair(alg).then(function (kp) {
        bGen.disabled = false;
        self.encKey = kp;
        self.encPriv.value = '';
        self.showEncInfo('Key pair generated for ' + alg + ' (kid ' + kp.kid + '). Share the public key below; the private key never leaves this tab.', kp);
      }, function () {
        bGen.disabled = false;
        self.showEncInfo(alg === 'Ed25519' ? 'This browser cannot create Ed25519 keys yet.' : 'Could not generate a key pair.');
      });
    });
    bSign.addEventListener('click', function () {
      var alg = self.encAlg.value;
      var hp = parseJson(self.encHeader.value || '{}');
      var pp = parseJson(self.encPayload.value || '{}');
      if (hp.error || !isPlainObject(hp.value)) return self.showEncInfo('Header must be a JSON object' + (hp.error ? ' (' + hp.error + ', line ' + hp.line + ')' : '') + '.');
      if (pp.error || !isPlainObject(pp.value)) return self.showEncInfo('Payload must be a JSON object' + (pp.error ? ' (' + pp.error + ', line ' + pp.line + ')' : '') + '.');
      var fam = ALGS[alg].family;
      var keyP;
      var header = hp.value;
      if (fam === 'HMAC') keyP = Promise.resolve(null);
      else if (self.encPriv.value.replace(/\s/g, '')) keyP = importSigningKey(alg, self.encPriv.value);
      else if (self.encKey) { header.kid = self.encKey.kid; keyP = Promise.resolve(self.encKey.privateKey); }
      else return self.showEncInfo('Generate a key pair or paste a private key first.');
      keyP.then(function (pk) {
        return sign(header, pp.value, { alg: alg, secret: self.encSecret.value, encoding: 'utf8', privateKey: pk });
      }).then(function (tok) {
        self.showEncInfo('Token created. It opens in the decoder with the matching key, so you can check it.', self.encPriv.value ? null : self.encKey, tok);
        self.input.value = tok;
        if (fam === 'HMAC') { self.modeSecret.checked = true; self.secret.value = self.encSecret.value; self.encoding.value = 'utf8'; }
        else if (self.encKey && !self.encPriv.value) { self.modeKey.checked = true; self.keyText.value = self.encKey.publicPem; }
        self.syncMode();
        self.run();
      }, function (e) {
        self.showEncInfo(e.message || 'Could not create the token.');
      });
    });
    syncAlg();
  };

  App.prototype.showEncInfo = function (msg, kp, token) {
    clear(this.encOut);
    this.encOut.appendChild(el('p', { text: msg }));
    var self = this;
    function block(title, text) {
      var head = el('div', { className: 'jwt-panel-head' }, [el('h4', { className: 'jwt-panel-title', text: title })]);
      var btn = el('button', { type: 'button', className: 'jwt-btn jwt-btn-sm', text: 'Copy' });
      head.appendChild(btn);
      var pre = el('pre', { className: 'jwt-json jwt-wrap', text: text });
      btn.addEventListener('click', function () { copyText(text, btn); });
      self.encOut.appendChild(el('div', { className: 'jwt-panel' }, [head, pre]));
    }
    if (token) block('Token', token);
    if (kp) {
      block('Public key (PEM)', kp.publicPem);
      block('Public key (JWK Set)', JSON.stringify({ keys: [kp.publicJwk] }, null, 2));
    }
  };

  /* ------------------------------------------------------------------ *
   * Boot
   * ------------------------------------------------------------------ */
  var api = {
    normalizeToken: normalizeToken, decode: decode, parseJson: parseJson, analyze: analyze, verify: verify,
    sign: sign, generateKeyPair: generateKeyPair, parseKeyMaterial: parseKeyMaterial, thumbprint: thumbprint,
    b64urlToBytes: b64urlToBytes, bytesToB64url: bytesToB64url, makeSample: makeSample, resolveJwks: resolveJwks,
    importSigningKey: importSigningKey, ALGS: ALGS
  };
  if (typeof window !== 'undefined') window.AptdotJwt = api;

  function boot() {
    var roots = document.querySelectorAll('.aptdot-jwt-app');
    for (var i = 0; i < roots.length; i++) {
      if (roots[i].getAttribute('data-ready')) continue;
      roots[i].setAttribute('data-ready', '1');
      new App(roots[i]);
    }
  }
  if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
    else boot();
  }
})();
