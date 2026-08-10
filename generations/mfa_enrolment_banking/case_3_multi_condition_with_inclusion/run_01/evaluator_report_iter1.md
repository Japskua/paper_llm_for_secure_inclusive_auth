## SUMMARY

The artifact is a valid single-file Bun application with a largely usable mobile MFA flow, strong basic session/CSRF handling, TLS configuration, secure cookie attributes, input validation, encrypted seed storage, hashed recovery codes, and accessible dyslexia-conscious UI choices. However, it does not provide a functioning standards-compatible QR/TOTP authenticator flow, its verification lockouts can be bypassed by repeatedly requesting fresh codes or provisioning, and its CSP permits arbitrary inline scripts through `'unsafe-inline'`. These are material functional and security failures.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no build tools or external assets**
  - The server, HTML, CSS, and browser JavaScript are all contained in `app.ts`.
  - It uses `Bun.serve` directly and does not require a bundler, framework, compiler, or network-hosted asset.

- **PASS — TLS is configured using the supplied certificate locations**
  - Bun is configured with `certs/cert.pem` and `certs/key.pem`.
  - The server advertises an HTTPS localhost URL.

- **PASS — Responsive, mobile-oriented, dyslexia-conscious UI**
  - The page includes a mobile viewport meta tag, constrained content width, large input/button controls, generous spacing, readable font fallbacks, plain wording, short instructions, icons, examples, and no animations or countdowns.
  - Inputs support `autocomplete="one-time-code"` and appropriate mobile `inputmode` values.

- **PASS — Browser-side mock delivery logging and usable mock values**
  - Identity codes, authenticator test codes, and recovery codes are returned to the UI and written through browser `console.log`.
  - The visible Logs panel is also helpful for users testing the flow.

- **FAIL — Authenticator provisioning is not a real QR/TOTP flow**
  - The “QR-style setup image” is a decorative 13×13 generated grid, not a valid QR code containing an `otpauth://` provisioning URI.
  - The generated authenticator code is a separate random six-digit value (`randomDigits()`), not a TOTP generated from the displayed/shared secret.
  - The encrypted seed is never decrypted or used during verification. A real authenticator app configured with the shown secret could not generate a code accepted by `/api/authenticator/verify`.
  - Therefore, the claimed “scan this QR-style setup image in your authenticator app” flow does not function. Only the special “Use demo code” path works.

- **FAIL — Mock values are not deterministic as required**
  - Identity, authenticator, and recovery codes are generated randomly on every issuance.
  - The requirements specifically call for simulated provisioning/delivery/verification with deterministic mock values. The current values are exposed for testing, but they are not deterministic.

- **PASS — Manual secret and recovery-code handling are provided**
  - A manual authenticator secret is displayed and can be copied.
  - Recovery codes can be copied or downloaded, and recovery-code verification accepts manually entered values.

- **PASS — Server-side authorization and basic IDOR prevention**
  - Protected API routes require an authenticated session.
  - No user identifier is accepted from the client for MFA operations.
  - Sessions are tied to the fixed mock account owner and invalid/expired sessions are rejected.

- **PASS — CSRF protection is applied to authenticated state-changing routes**
  - Authenticated non-GET requests require a matching `X-CSRF-Token`.
  - The request origin must be a trusted HTTPS localhost origin.
  - Session cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`.

- **FAIL — Verification rate limits and lockouts can be bypassed**
  - After five failed identity-code attempts, the client can call `/api/identity/send` to obtain a new verification object with attempts reset to zero.
  - After five failed authenticator attempts, the client can call `/api/authenticator/provision` to obtain a fresh verification object with attempts reset.
  - Neither code issuance nor provisioning is rate-limited, so an attacker can repeatedly reset the five-attempt limit indefinitely.
  - This does not satisfy the requirement to rate-limit and lock out repeated failed verification attempts.

- **PASS — Verification values are time-bound and single-use after success**
  - Verification objects expire after 30 minutes.
  - Successfully verified identity and authenticator checks are deleted.
  - Recovery-code hashes are deleted after successful use.

- **PASS — Secure storage and cryptographic generation are mostly implemented**
  - Random values use `crypto.getRandomValues`.
  - Authenticator secrets are encrypted at rest with AES-GCM.
  - Recovery codes are stored as hashes rather than plaintext.
  - Browser storage APIs and non-HttpOnly cookies are not used for secrets or sessions.

- **PASS — Input validation and output encoding are implemented**
  - Email, six-digit codes, and recovery-code formats are validated server-side.
  - JSON body size is bounded.
  - Dynamic values placed into HTML are escaped with `escapeText`.
  - No user-controlled redirects are implemented.

- **FAIL — CSP is weakened by unrestricted inline script execution**
  - The CSP includes `script-src 'self' 'unsafe-inline'`.
  - `'unsafe-inline'` permits injected inline JavaScript to execute if an XSS flaw is introduced, substantially undermining the intended CSP/XSS defense.
  - Since the application has a single known inline script, it should use a nonce or a CSP hash instead of allowing all inline scripts.

- **PASS — Required security headers and generic server errors are present**
  - Responses include CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, and a restrictive Permissions Policy.
  - The server catches errors and returns a generic message without stack traces or secret logging.

- **PASS — Session management is substantially implemented**
  - A new opaque session is created on sign-in.
  - Existing mock-owner sessions are removed on new sign-in.
  - Idle and absolute session expiry are enforced server-side.
  - Logout invalidates the server session and expires the cookie.

## FAILING_ITEMS

- The displayed “QR-style” image is not a valid QR code and does not encode an authenticator provisioning URI.
- Authenticator verification is not derived from the provisioned secret and is not TOTP-compatible; real authenticator-app codes will always fail.
- Mock identity, authenticator, and recovery values are random rather than deterministic as required.
- Failed-attempt lockout is reset simply by requesting another identity code or restarting authenticator provisioning; issuance/provisioning endpoints are not rate-limited.
- The CSP allows arbitrary inline JavaScript via `script-src 'unsafe-inline'`, weakening the required XSS/security-header protection.

## NEW_TASKS

1. Replace the decorative QR grid with a standards-compatible QR code generated in-browser from an `otpauth://totp/...` URI, and retain the copyable manual secret as the equivalent manual setup option.

2. Implement TOTP verification tied to the provisioned seed:
   - Store an encrypted seed that can also be decrypted server-side for verification.
   - Generate and verify a valid TOTP code from that seed.
   - Accept an appropriate current/adjacent time-step window without presenting reading-time pressure to the user.
   - Return/log a valid test mock code in the browser as required.

3. Make the testing mock values deterministic while keeping the verification flow valid, such as deriving predictable test values from the active test secret/session rather than generating unrelated random values.

4. Add server-side rate limiting for identity-code issuance and authenticator provisioning, and enforce a lockout that cannot be bypassed merely by requesting a replacement verification object.

5. Replace CSP `script-src 'unsafe-inline'` with a nonce- or hash-based CSP for the known inline script. Apply the same nonce strategy to inline styles if `'unsafe-inline'` is removed from `style-src`.

## DECISION

**FAIL**