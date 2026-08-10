## SUMMARY

The artifact is a single-file Bun HTTPS SPA with a mostly complete MFA enrolment flow, secure headers, session/CSRF controls, validation, rate limiting, encrypted TOTP-secret storage, hashed recovery codes, and dyslexia-conscious mobile UI. However, the presented “QR code” is not a standards-compliant QR code and cannot be scanned by an authenticator application. Since the UI explicitly instructs users to scan it, this is a functional failure of the authenticator-provisioning flow.

## FUNCTIONAL_CHECK

- **Single `app.ts` containing Bun server, HTML, CSS, and vanilla browser JavaScript — PASS**  
  The provided implementation is contained in one TypeScript file and embeds the HTML, CSS, and client-side JavaScript. It uses Bun directly and has no framework, bundler, compiler step, or external asset dependency.

- **HTTPS/TLS using the required certificate paths — PASS**  
  `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`, binds to `localhost`, and uses port `3000`.

- **Mobile-responsive, dyslexia-conscious SPA UI — PASS**  
  The UI has a constrained mobile-width shell, readable font sizing, increased letter spacing, generous spacing, plain-language copy, examples for expected inputs, icons paired with text, focused primary actions, and no animations or reading timers.

- **Sign-in and identity-verification flow works — PASS**  
  The sign-in flow validates credentials, establishes a session, sends a simulated identity code, permits requesting another code, validates the 6-digit code, prevents re-use, expires codes, and applies failed-attempt lockout.

- **Authenticator setup supports manual setup-key use — PASS**  
  The server creates and returns an `otpauth://` URI and setup key; the UI supports revealing and copying the setup key and provides a manual-setup instruction. The setup key is encrypted at rest server-side.

- **Authenticator QR-code option works — FAIL**  
  `provisioningQR()` does not generate a QR code that encodes the provisioning URI. It creates a pseudo-random module grid from a hash of the URI and labels it as a QR code. It lacks QR encoding features such as byte-mode encoding, Reed–Solomon error correction, format/version information, masking, and proper placement rules. Authenticator apps cannot scan it.  
  Additionally, the drawing dimensions are incorrect: `n = 33`, `quiet = 2`, and `size = 9` require a `37 × 37` module canvas (`333 × 333` pixels), but the canvas is only `297 × 297`; modules at the right and bottom are clipped.

- **Authenticator confirmation and OTP verification work — PASS**  
  TOTP is calculated using HMAC-SHA-1 and 30-second counters, accepts a narrow time window, rejects re-used counters, and rate-limits failures. In academic mode, deterministic test values are returned to the browser and logged in the browser console as required.

- **Recovery-code flow works and stores codes securely — PASS**  
  Recovery codes are generated, displayed only after user interaction, copyable, logged in the browser console in academic mode, and stored server-side as SHA-256 hashes rather than plaintext.

- **State-changing MFA endpoints have authorization and CSRF controls — PASS**  
  MFA-changing API routes call `protect()`, which requires an active session, checks the request origin when supplied, and validates an anti-CSRF token. No user identifier is accepted from the client, avoiding IDOR through manipulated account IDs.

- **Session management and cookie attributes — PASS**  
  Session identifiers are generated cryptographically at sign-in, use `HttpOnly`, `Secure`, and `SameSite=Strict`, have idle and absolute expiry checks, and are removed by the logout endpoint.

- **Security response headers and CORS behavior — PASS**  
  Responses include CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, and no permissive CORS headers. Cross-origin requests are therefore not allowed.

- **Input validation and output-safety measures — PASS**  
  Email, password, and OTP input are validated server-side. The browser UI uses DOM APIs and `textContent` rather than interpolating server content into HTML, reducing reflected/DOM XSS exposure.

- **No secret persistence in browser storage — PASS**  
  The code does not use `localStorage` or `sessionStorage`. Setup and recovery values are held in memory while the current UI is displayed.

- **Internal routing/navigation and retry behavior — PASS**  
  Client routing is state-based and calls working API endpoints. Users can retry code entry, request a new identity code, get a refreshed authenticator test code, reveal/hide sensitive values, and copy values.

- **Code validity / runtime viability — PASS, except for the QR implementation defect**  
  The Bun server and browser code are structurally valid TypeScript/JavaScript. No compilation dependency is present. The invalid QR generation is a functional defect rather than a syntax/runtime startup error.

## FAILING_ITEMS

- The “Scan this QR code” authenticator-provisioning feature is non-functional. `provisioningQR()` produces a deterministic pseudo-random visual pattern, not a QR-code-standard encoding of the `otpauth://` URI.
- The pseudo-QR canvas is geometrically clipped: its declared size is too small for the configured module count plus quiet zone, so part of the pattern is not rendered.
- The UI tells users to scan an image that cannot be scanned, which conflicts with the requirement that offered QR options function correctly and reduces confidence for users relying on the lower-reading-load scan path.

## NEW_TASKS

1. Replace `provisioningQR(uri)` with a dependency-free, standards-compliant QR encoder that encodes the full `otpauth://` provisioning URI, including valid QR data encoding, error correction, masking, format information, quiet zone, and correct canvas dimensions.
2. Verify the generated QR code using at least one authenticator application or QR decoder, confirming that it imports the same secret and issuer shown in the manual setup path.
3. If a compliant QR encoder is not implemented, remove the scan-QR UI and wording entirely, leaving the already functional reveal/copy manual setup-key flow.

## DECISION

**FAIL**