<?php
/**
 * Aptdot JWT Decoder & Verifier.
 *
 * Shortcode: [aptdot_jwt_decoder]
 * Page slug: jwt-decoder (under /tools/)
 *
 * The tool runs entirely in the browser (assets/js/jwt-decoder.js). PHP only prints
 * the container, loads the two assets and adds the WebApplication JSON-LD in <head>.
 */
if ( ! defined( 'ABSPATH' ) ) exit;

add_shortcode( 'aptdot_jwt_decoder', function() {
    wp_enqueue_style( 'aptdot-jwt-decoder-css', APTDOT_SUITE_URL . 'assets/css/jwt-decoder.css', [], APTDOT_SUITE_VERSION );
    wp_enqueue_script( 'aptdot-jwt-decoder-js', APTDOT_SUITE_URL . 'assets/js/jwt-decoder.js', [], APTDOT_SUITE_VERSION, true );

    ob_start();
    ?>
    <div class="aptdot-jwt-app google-anno-skip" data-tool="jwt-decoder">
        <p class="jwt-loading">Loading the JWT decoder&hellip;</p>
        <noscript><p>The JWT decoder needs JavaScript. It runs entirely in your browser; nothing is sent to a server.</p></noscript>
    </div>
    <?php
    return ob_get_clean();
});

add_action( 'wp_head', function() {
    if ( is_page( 'jwt-decoder' ) ) {
        ?>
        <script type="application/ld+json">
        {
          "@context": "https://schema.org",
          "@type": "WebApplication",
          "name": "JWT Decoder & Verifier",
          "url": "https://www.aptdot.com/tools/jwt-decoder/",
          "description": "Free JWT decoder and verifier that runs entirely in your browser. Decodes the header and payload, explains every claim, checks exp, nbf and iat, flags security risks such as alg none, weak secrets and key-injection headers, and verifies HS, RS, PS, ES and Ed25519 signatures with a secret, PEM key, certificate, JWK or JWK Set.",
          "applicationCategory": "DeveloperApplication",
          "operatingSystem": "Any",
          "browserRequirements": "Requires JavaScript and the Web Crypto API (any current browser).",
          "isAccessibleForFree": true,
          "featureList": [
            "Decode JWT header and payload (JWS and JWE header)",
            "Claim explanations from the IANA JWT registry",
            "Expiry, not-before and issued-at checks with clock tolerance",
            "Security checks: alg none, weak HMAC secrets, algorithm confusion, jku, jwk and kid injection, duplicate claims",
            "Signature verification: HS256-512, RS256-512, PS256-512, ES256-512, Ed25519",
            "Keys: secret, PEM public key, X.509 certificate, JWK, JWK Set, issuer discovery",
            "Create test tokens with browser-generated keys"
          ],
          "offers": {
            "@type": "Offer",
            "price": "0",
            "priceCurrency": "USD"
          },
          "creator": {
            "@type": "Organization",
            "name": "Aptdot",
            "url": "https://www.aptdot.com"
          }
        }
        </script>
        <?php
    }
} );
