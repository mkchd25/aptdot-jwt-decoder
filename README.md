# JWT Decoder & Verifier

A free JWT decoder that runs entirely in your browser: decode the header and payload, read every claim in plain language, check expiry, verify the signature and spot security problems such as `alg: none`, weak secrets and key-injection headers.

[![Tests](https://github.com/mkchd25/aptdot-jwt-decoder/actions/workflows/test.yml/badge.svg)](https://github.com/mkchd25/aptdot-jwt-decoder/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Use it online: [aptdot.com/tools/jwt-decoder](https://www.aptdot.com/tools/jwt-decoder/)**

## Features

- **Decode** signed tokens (JWS), the header of encrypted tokens (JWE), nested tokens and `b64: false` tokens. Pasting a whole `Authorization: Bearer ...` header works.
- **Explain** each claim using the IANA JWT claims registry, with times shown in UTC and as "in 12 minutes" or "3 days ago".
- **Check times**: expired, not yet valid, issued in the future, missing `exp`, lifetimes over 24 hours. You can choose the moment to check at and a clock tolerance.
- **Verify signatures** with your browser's Web Crypto:

  | Algorithms | Keys you can use |
  | :--- | :--- |
  | HS256, HS384, HS512 | Secret as text, base64url or base64 |
  | RS256-512, PS256-512 | PEM public key, PKCS#1 key, X.509 certificate, JWK, JWK Set |
  | ES256, ES384, ES512 | PEM public key, X.509 certificate, JWK, JWK Set |
  | Ed25519 (and the older name EdDSA) | PEM public key, JWK, JWK Set |

  Keys can also be fetched from the issuer's OpenID discovery document or JWKS URL.
- **Security checks** based on [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725): `alg: none`, algorithm confusion (a public key pasted as an HMAC secret), weak HMAC secrets, `jku`/`x5u`/embedded `jwk` headers, path traversal or SQL characters in `kid`, unknown `crit` parameters, duplicate claims, wrong time formats, RSA keys under 2048 bits and readable personal data.
- **Create test tokens** with any supported algorithm. Key pairs are generated in the browser and shown as PEM and JWK.

## Privacy

The token and keys never leave your browser: nothing is uploaded, stored or put in a share link, and there is no analytics code in the tool.

The only network request is the optional **Fetch keys** button. It requests the issuer's public keys over https, without cookies or a referrer, and never sends the token.

Browser extensions and other scripts on a page can still read anything you paste, so use test tokens or tokens you can revoke.

## Run it locally

Download this repository and open `index.html` in a browser. There is no build step and no runtime dependency: everything is in [`src/jwt-decoder.js`](src/jwt-decoder.js) and [`src/jwt-decoder.css`](src/jwt-decoder.css).

To embed it in your own page, include both files and add a container:

```html
<link rel="stylesheet" href="jwt-decoder.css">
<div class="aptdot-jwt-app"></div>
<script src="jwt-decoder.js"></script>
```

[`wordpress/jwt-decoder.php`](wordpress/jwt-decoder.php) shows how aptdot.com loads it as a WordPress shortcode.

## Tests

```bash
npm ci
npm test                      # 217 unit, interoperability and safety tests
npx playwright install chromium
npm run test:browser          # 24 checks in a real browser
```

The unit tests check the results against the [jose](https://github.com/panva/jose) and [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) libraries for every algorithm and key format, use certificates and keys made with OpenSSL, run a fuzz test with 3,000 malformed inputs and confirm that hostile tokens cannot inject HTML. The browser tests also confirm that pasting a token makes no network request and stores nothing.

## Test tokens

The [JWT Claims Reference dataset](https://www.aptdot.com/datasets/jwt-claims-reference/) has 8 signed test tokens, 2 valid and 6 that verification code must reject, each with the exact error that PyJWT and jsonwebtoken raise. Source: [aptdot-datasets](https://github.com/mkchd25/aptdot-datasets).

## Security and issues

- Please report security problems privately, as described in [SECURITY.md](SECURITY.md).
- Bugs and ideas: [open an issue](https://github.com/mkchd25/aptdot-jwt-decoder/issues/new/choose).

## License

[MIT](LICENSE) © 2026 Aptdot
