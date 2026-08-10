## SUMMARY

The artifact is a single-file Bun HTTPS SPA with many strong security and accessibility foundations: TLS configuration, secure cookie attributes, session expiry, CSRF tokens for authenticated POST requests, encrypted OTP secrets, hashed recovery codes, input validation, rate limits, security headers, mobile styling, and clear step-based UI. However, it does not meet all functional requirements: the displayed “QR code” is not a real, scannable QR code, and the required browser-console disclosure of simulated OTP and recovery codes is disabled by default and only available through an undocumented opt-in server environment variable. There are also MFA-flow authorization/state checks that can be bypassed after a new sign-in if an earlier provisioning record exists.

## FUNCTIONAL_CHECK

- **PASS — Single-file app and zero-compilation compliance.**  
  The server, HTML, CSS, and client-side JavaScript are all contained in `app.ts`. It runs directly with Bun and does not require a bundler, framework, build tool, package, or external frontend asset.

- **PASS — Bun HTTPS server uses the specified certificate paths.**  
  `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`, as required.

- **PASS — Mobile-responsive, dyslexia-conscious UI.**  
  The UI uses a constrained mobile layout, generous spacing, large inputs/buttons, clear labels, plain wording, examples for entered values, consistent step labels, no timers or animated elements, and browser autofill attributes.

- **PASS — Manual authenticator setup is supported.**  
  The setup secret is returned to the UI, can be revealed/hidden, and can be copied with `navigator.clipboard`. The OTP input supports `autocomplete="one-time-code"`.

- **FAIL — A functional QR-code option is not provided.**  
  The `qr()` function draws deterministic pseudo-random blocks and finder-like squares on a canvas. This is explicitly described in code as a “QR-style visual,” not an encoded QR symbol. Authenticator applications will not be able to scan `result.provisioningUri`, so the scan-first setup path does not work.

- **FAIL — Browser-console test mocks do not satisfy the stated delivery requirement.**  
  The requirements explicitly state that OTPs and backup recovery codes “must be returned to UI and shown in the `console.log` there” for testing. In this implementation, secrets are not logged by default. OTP disclosure only happens when `MFA_TEST_ONLY_DISCLOSURE=true`, and recovery codes are logged only behind the same flag. This behavior is not part of the stated requirements and means a normal evaluator run cannot obtain the required console mocks.

- **FAIL — The mock OTP is not consistently returned to the UI.**  
  `provision()` only includes `testOnlyOtp` when `MFA_TEST_ONLY_DISCLOSURE=true`. The normal response contains the setup secret and provisioning URI, but not the deterministic/mock OTP required for testing. The client only logs the OTP if that optional field exists.

- **PASS — Authenticator verification works cryptographically.**  
  The server generates a CSPRNG Base32 secret, uses HMAC-SHA-1 TOTP with a 30-second period, accepts a narrowly bounded clock skew, validates six-digit entries, expires provisioning after ten minutes, and prevents reuse of a successful provisioning verification.

- **PASS — Recovery codes are generated securely and are single-use.**  
  Recovery codes use CSPRNG values, are stored only as salted PBKDF2 hashes, are invalidated after successful use, and replacement generation invalidates old records.

- **PASS — Input validation and output-safety protections are largely present.**  
  Email, phone, OTP, and recovery-code formats are validated server-side. Client-controlled account identifiers are rejected on authenticated state-changing routes. Server messages do not reflect raw user input, and the client writes messages through `textContent`.

- **PASS — Session and request security controls are substantially implemented.**  
  Sessions are random, server-side, rotated on sign-in, have idle and absolute expiry, and are invalidated on logout. Session cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`. Authenticated POST routes require a session CSRF token and same-origin validation.

- **FAIL — Identity-confirmation state is not enforced on all MFA provisioning actions.**  
  `/api/mfa/provision` requires `current.s.identity`, but `/api/mfa/reissue` and `/api/mfa/verify` do not. Because account state is retained in the global `accounts` map, a user who signs in again can potentially call reissue or verify against an existing `account.provision` without completing `/api/identity` in that new session. This breaks the intended step order and makes the identity-confirmation state inconsistent.

- **PASS — Rate limiting and lockout controls exist for verification attempts.**  
  OTP and recovery-code verification are limited to five failures, followed by a five-minute lockout. Provisioning-key reissue is also capped.

- **PASS — Secure response headers and restrictive CORS behavior are implemented.**  
  CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, and `Cache-Control: no-store` are present. CORS is not broadly enabled and only conditionally permits trusted local HTTPS origins.

- **PASS — Secrets are not persisted in browser storage or ordinary cookies.**  
  The code does not use `localStorage`, `sessionStorage`, or non-HttpOnly cookies for OTP seeds, recovery codes, or sessions.

- **PASS — Internal SPA navigation functions.**  
  The step transitions, settings page, recovery-code verification page, back navigation, and logout flow are implemented through functioning button handlers.

## FAILING_ITEMS

- The setup canvas is not a valid QR code and cannot be scanned by an authenticator app.
- Required test OTP and recovery-code console logging is disabled by default and depends on `MFA_TEST_ONLY_DISCLOSURE=true`, which is not specified in the requirements.
- A test OTP is not returned in the normal provisioning response/UI flow.
- `/api/mfa/reissue` does not require `current.s.identity`.
- `/api/mfa/verify` does not require `current.s.identity`, allowing an existing provision record to be verified after a fresh sign-in without repeating the identity-confirmation step.

## NEW_TASKS

1. Replace the custom `qr()` pseudo-random canvas renderer with an actual QR-code encoder implemented inline in `app.ts`, encoding the exact `otpauth://` provisioning URI returned by `/api/mfa/provision`.
2. Implement the required deterministic test mock delivery behavior so provisioning returns a test OTP and recovery generation returns recovery codes to the UI, and log both values with `console.log` in the browser as required.
3. If secret logging must be limited outside evaluation mode, make the mode explicit, enabled by the evaluator’s normal run configuration, and ensure the required behavior is not silently disabled by default.
4. Add `if (!current.s.identity) return fail(403, "Confirm your identity before requesting a fresh setup key.");` to `/api/mfa/reissue`.
5. Add `if (!current.s.identity) return fail(403, "Confirm your identity before verifying your authenticator.");` to `/api/mfa/verify`.

## DECISION

**FAIL**