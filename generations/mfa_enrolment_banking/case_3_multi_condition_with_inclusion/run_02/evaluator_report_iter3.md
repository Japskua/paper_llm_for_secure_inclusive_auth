## SUMMARY

The artifact is a single `app.ts` Bun application with inline HTML, CSS, and vanilla browser JavaScript. It implements most of the MFA flow and many server-side security controls well, including authenticated sessions, CSRF checks, encrypted TOTP secrets, hashed recovery codes, secure headers, input validation, and single-use verification protections. However, it does not provide a real scannable QR code, allows identity-verification rate limiting to be bypassed through resend, and does not fully meet the deterministic browser-side mock and reveal/hide UX requirements. These issues prevent acceptance.

## FUNCTIONAL_CHECK

- **Single-file Bun server with inline HTML, CSS, and JavaScript: PASS**
  - The entire application is contained in `app.ts`.
  - Bun directly serves the generated HTML and runs the server code without bundlers, frameworks, external assets, or a separate compilation/build step.

- **HTTPS/TLS server using the supplied certificate paths: PASS**
  - `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`.
  - The server does not expose a plaintext HTTP listener in this artifact.

- **Responsive, mobile-oriented, readable UI: PASS**
  - The page includes a mobile viewport meta tag, a narrow `main` content width, responsive padding, accessible input sizing, generous spacing, and legible font sizing.
  - The flow uses short instructions, icons, examples, help text, and a clear primary action per main step.

- **Dyslexia-inclusive reveal, hide, retry, and re-request support: FAIL**
  - Identity codes can be re-requested.
  - Setup details can be revealed, but cannot be hidden again after selecting “Show setup details.”
  - The recovery-code screen also has no mechanism to hide sensitive codes after viewing them.
  - The requirement explicitly calls for users to be able to “reveal, hide and re-request codes without penalty.”

- **Authenticator provisioning with QR and manual setup support: FAIL**
  - Manual setup is supported: the setup secret and provisioning URI are displayed and can be copied.
  - However, the rendered “QR code” is not a standards-compliant QR code and does not encode `setup.provisioningUri`.
  - The `qr()` function creates a decorative 15×15 pattern based only on row/column arithmetic. Authenticator apps cannot scan it to provision the account.
  - Additionally, its per-cell inline `style="opacity:..."` is blocked by the configured CSP because `style-src` only permits nonce-bearing `<style>` elements, not style attributes. This makes the displayed graphic even less valid as a QR representation.

- **Identity OTP delivery, verification, resend, and browser simulation logging: PARTIAL / FAIL**
  - Identity OTPs are generated, returned to the authenticated browser client, shown in the UI’s Logs panel, and passed to `console.log`.
  - Codes are time-bound and single-use.
  - However, identity OTPs are random by default. Deterministic mock behavior only occurs when the undeclared optional environment setting `EVALUATOR_DEMO=true` is provided, and even then identity OTPs remain random.
  - The requirements call for deterministic mock values and browser-console simulation behavior for testing.

- **Authenticator OTP verification and replay prevention: PASS**
  - TOTP uses RFC 6238-style HMAC-SHA1 with six digits and 30-second intervals.
  - The server tracks accepted counters in `acceptedTotpCounters`, preventing reuse of a TOTP counter.
  - Verification accepts a limited clock-skew window and rejects already-used codes.

- **Recovery-code generation, display, copying, regeneration, and single use: PASS**
  - Recovery codes are shown after authenticator confirmation and can be copied.
  - Codes are hashed with PBKDF2 before storage.
  - Pending visible recovery codes are encrypted at rest.
  - Regeneration invalidates prior recovery-code hashes.
  - Successful recovery-code use marks the matched code as used.

- **Server-side authorization and IDOR prevention: PASS**
  - MFA endpoints require a valid `mfa_session`.
  - The session’s `userId` is checked against the internal authenticated account owner.
  - Client-supplied user identifiers are not accepted by MFA endpoints, preventing manipulated account identifiers and straightforward IDOR.

- **CSRF protection on state-changing MFA actions: PASS**
  - State-changing requests require the `X-CSRF-Token` header to match the token stored in the authenticated server session.
  - Session cookies use `SameSite=Strict`, which provides additional CSRF defense.

- **Secure cookie and session management: PASS**
  - Session cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - Sessions have 30-minute idle expiration and 8-hour absolute expiration.
  - A fresh random session identifier is created at sign-in.
  - Logout deletes the server-side session and clears the cookie.

- **Rate limiting and lockout for repeated verification failures: FAIL**
  - The identity verification endpoint locks after five failed attempts.
  - However, `/api/identity/resend` calls `successAttempt(session)`, resetting `session.failures` to zero without a successful identity verification.
  - An attacker can submit failed identity codes, request a resend, and repeat indefinitely, bypassing the intended lockout.
  - This violates the requirement to rate-limit and lock out repeated failed verification attempts.

- **Security headers, clickjacking protections, CORS restriction, and generic errors: PASS**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, no-referrer policy, and a restrictive permissions policy are present.
  - No permissive CORS response headers are emitted.
  - Exceptions are caught and converted into generic responses rather than verbose stack traces.

- **Cryptographic storage and random generation controls: PASS**
  - TOTP secrets are encrypted using AES-GCM.
  - Recovery codes are stored using PBKDF2 hashes with unique salts.
  - Random production secrets, sessions, CSRF tokens, IVs, and codes use `crypto.getRandomValues`.
  - Browser storage APIs and non-HttpOnly cookies are not used for sensitive state.

- **Input validation, output encoding, and redirect safety: PASS**
  - Server input is constrained with explicit regular expressions for OTP and recovery-code formats.
  - Credentials are bounded before PBKDF2 processing.
  - Dynamic browser-rendered values are escaped through `esc()`.
  - There is no user-controlled redirect mechanism or external redirect target.

- **No external network calls or external assets: PASS**
  - The browser only calls same-origin `/api/...` endpoints.
  - No third-party scripts, stylesheets, APIs, images, or QR libraries are used.

## FAILING_ITEMS

- The displayed QR graphic is decorative rather than a valid QR code encoding the `otpauth://` provisioning URI. It cannot be scanned by an authenticator app.
- The CSP blocks the QR generator’s inline `style="opacity:..."` declarations because `style-src` does not allow inline style attributes.
- Identity verification lockout can be bypassed because `/api/identity/resend` resets failed-attempt state through `successAttempt(session)`.
- The default application behavior does not provide deterministic simulated OTP/mock values as required. The optional `EVALUATOR_DEMO` mode is not enabled by default, and identity OTPs remain random even in that mode.
- Sensitive setup details can be revealed but not hidden again, and recovery codes cannot be hidden after display, contrary to the reveal/hide requirement.

## NEW_TASKS

1. Replace the decorative `qr()` output with a real standards-compliant QR encoder implemented within `app.ts`, and encode the exact `setup.provisioningUri` into the QR code.
2. Update QR rendering so it remains CSP-compliant, such as by using CSS classes/generated markup rather than blocked inline `style` attributes, or by changing CSP only in a secure, narrowly scoped way.
3. Remove the `successAttempt(session)` call from `/api/identity/resend`; preserve the existing failure count and reject resend requests while `lockedUntil` is active.
4. Make the evaluator/demo flow deterministic by default or through an explicit documented launch configuration that is guaranteed for evaluation, including deterministic identity OTP and authenticator test-code behavior while retaining cryptographically secure production mode.
5. Add explicit Show/Hide toggles for authenticator setup details and recovery codes, ensuring hidden secrets are removed or obscured from the visible UI while retaining safe retry and re-request actions.

## DECISION

**FAIL**