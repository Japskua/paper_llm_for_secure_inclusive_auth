## SUMMARY

The artifact is a well-structured single-file Bun application with a responsive mobile UI, HTTPS/TLS configuration, session-based ownership checks, CSRF validation, CSP and other security headers, encrypted TOTP secrets, hashed recovery codes, and browser-side mock logging. The main MFA enrolment flow works. However, it does not fully meet the verification-code single-use and failed-attempt lockout requirements: OTP consumption is vulnerable to concurrent replay, and malformed verification submissions bypass failure counters. Lock counters also do not reset correctly after the lock period expires.

## FUNCTIONAL_CHECK

- **Single `app.ts` artifact with Bun server, HTML, CSS, and vanilla browser JavaScript: PASS**
  - The entire server and SPA are contained in one TypeScript file. There are no frameworks, bundlers, external assets, database dependencies, or network calls.

- **HTTPS/TLS enforcement using the supplied certificate paths: PASS**
  - `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`, and no plaintext HTTP listener is created.

- **Responsive mobile web UI and MFA enrolment flow: PASS**
  - The UI includes sign-in, identity verification, authenticator secret creation, OTP verification, recovery-code display, settings, regeneration, recovery verification, and logout.
  - CSS includes a narrow-screen media query and mobile-legible sizing.

- **Mock OTP/provisioning/recovery values are available for testing and logged in the browser: PASS**
  - The identity code, provisioning secret/current OTP, recovery codes, and regenerated recovery codes are returned to the UI and passed to browser `console.log`.
  - The flows can be completed using the displayed/logged mock values.

- **Manual authenticator-secret entry is supported: PASS**
  - The verification page permits manually supplying the setup secret and validates it against the provisioned secret.

- **Internal navigation and routes function without open redirects: PASS**
  - Client navigation uses a restricted hash-page allow-list.
  - Server-side non-API routes are explicitly allow-listed.
  - There are no user-controlled redirect targets.

- **Server-side authorization and IDOR prevention for MFA endpoints: PASS**
  - MFA operations derive the account exclusively from the authenticated server-side session.
  - Client-provided account IDs are not accepted.
  - MFA status, provisioning, verification, recovery-code use, and regeneration require the session owner and identity verification.

- **CSRF protections for state-changing operations: PASS**
  - State-changing endpoints require a valid session CSRF token and a trusted same-origin HTTPS `Origin`.
  - The session cookie uses `SameSite=Strict`.

- **Secure response headers and CORS restrictions: PASS**
  - CSP with per-response nonce, HSTS, `X-Content-Type-Options`, `X-Frame-Options`, `frame-ancestors 'none'`, `Referrer-Policy`, and restrictive `Permissions-Policy` are set.
  - CORS is only reflected for a same-origin trusted HTTPS localhost origin.

- **Secure session handling: PASS**
  - Session cookies are `HttpOnly`, `Secure`, `SameSite=Strict`, and use the `__Host-` prefix correctly.
  - Sessions have idle and absolute expiry checks.
  - The session ID is rotated after successful sign-in.
  - Logout invalidates the server session and expires the cookie.
  - No secrets or session IDs are stored in browser storage.

- **Cryptographic storage and random-value generation: PASS**
  - Session IDs, CSRF tokens, identity codes, provisioning secrets, and recovery-code source values use `crypto.getRandomValues`.
  - TOTP shared secrets are AES-GCM encrypted at rest.
  - Recovery codes are stored as peppered SHA-256 digests rather than plaintext.
  - TOTP verification uses HMAC-SHA-1 in the normal RFC-style TOTP pattern.

- **Input validation and XSS/injection protections: PASS**
  - JSON request bodies are size-bounded.
  - Email, phone, OTP, recovery-code, and manual-secret formats are validated server-side.
  - No SQL/database query surface exists.
  - Dynamic browser values are inserted through `textContent` and DOM APIs rather than interpolated as untrusted HTML.

- **Verification codes and OTPs are single-use: FAIL**
  - Identity verification codes and recovery codes are consumed correctly.
  - However, `/api/mfa/verify` checks `p.used` before asynchronous `decrypt()` and `otp()` operations, then marks it used only afterward. Concurrent requests using the same pending secret and OTP can both pass the pre-check before either request sets `p.used=true`.
  - The TOTP value itself is not recorded as consumed. This leaves a concurrent replay race contrary to the single-use requirement.

- **Rate limiting and lockout of repeated failed authentication/verification attempts: FAIL**
  - Invalid six-digit OTP and recovery-code guesses increment the MFA failure count, but malformed input returns early before `failMfa()` is called.
  - For example, malformed OTP input, malformed recovery-code input, malformed identity-code input, or too-short sign-in passwords can be repeatedly submitted without advancing the relevant failure counter.
  - This means repeated failed authentication/verification submissions are not consistently rate-limited or locked out.

- **Lockout lifecycle behaves correctly after lock expiry: FAIL**
  - `failedMfa`, `identityFailures`, and `loginFailures` are not reset when their respective lock timers expire.
  - Once a lock expires, the next invalid attempt increments an already-maxed counter and immediately creates another lock. This prevents a normal new attempt window after the stated lock duration.

## FAILING_ITEMS

- **Concurrent MFA OTP replay is possible.**
  - `/api/mfa/verify` does not atomically reserve or consume the pending provisioning challenge before awaiting cryptographic operations.
  - Two concurrent requests with the same valid OTP can both succeed and each issue a separate set of recovery codes.

- **Malformed failed verification/authentication attempts bypass lockout counters.**
  - Validation failures occur before failure-count increments in sign-in, identity verification, TOTP verification, and recovery-code verification.
  - An attacker can submit unlimited malformed values without triggering the configured `MAX`/`LOCK` controls.

- **Failure counters remain at the threshold after lock expiry.**
  - Expired lockouts do not reset counters, so the first failed attempt after expiry immediately locks the account/session again.

## NEW_TASKS

1. Make MFA provisioning verification single-use atomically: reserve or mark the pending challenge consumed before asynchronous decrypt/TOTP validation, restore it only if appropriate on a failed validation, and ensure only one successful request can issue recovery codes.

2. Update sign-in, identity-code verification, authenticator-code verification, and recovery-code verification so every authenticated failed verification attempt—including structurally invalid entries—contributes to the applicable rate-limit/lockout counter while retaining generic error responses.

3. Add lock-expiry handling that resets `loginFailures`, `identityFailures`, and MFA session failure counts when their corresponding lock period has elapsed, before processing the next attempt.

## DECISION

FAIL