## SUMMARY

The artifact is a strong single-file Bun MFA enrolment implementation with responsive mobile UI, HTTPS/TLS setup, secure headers, session cookies, CSRF validation, server-side ownership checks, encrypted TOTP secrets, hashed recovery codes, input validation, and browser-only test logging. However, it does not fully enforce single-use verification codes under concurrent requests: asynchronous verification logic permits a race where the same identity or TOTP code can be accepted more than once. This violates the verification-code single-use requirement.

## FUNCTIONAL_CHECK

- **Single-file Bun application with inline HTML, CSS, and vanilla browser JavaScript — PASS**
  - The complete server, HTML template, CSS, and client-side JavaScript are contained in `app.ts`.
  - No frameworks, bundlers, compilers, external assets, or external network calls are used.

- **Mobile-responsive and legible MFA enrolment UI — PASS**
  - The page includes a viewport meta tag, constrained mobile-friendly layout, responsive CSS, readable font sizes, large form controls, and accessible labels/error regions.

- **Sign-in, identity verification, authenticator provisioning, TOTP confirmation, recovery-code display, regeneration, recovery verification, and logout flows work — PASS**
  - The client routes through working SPA states and calls matching API endpoints.
  - Manual TOTP-secret entry is supported via the displayed setup key.
  - OTP and recovery-code mock values are surfaced to the browser console/log panel as required for testing.

- **Broken Access Control: server-side authorization and no IDOR — PASS**
  - MFA endpoints use `authenticated(request)` and derive the user from the server-side session.
  - Request bodies reject `userId` and `accountId`.
  - No user-controlled identifier is used to load or mutate MFA state.

- **Broken Access Control: CSRF protection for state-changing requests — PASS**
  - Mutating endpoints require both a server-issued CSRF token and an allowed origin.
  - The session cookie uses `SameSite=Strict`.

- **Security Misconfiguration: required security headers and clickjacking protection — PASS**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, and `Cache-Control: no-store` are set.
  - CSP nonces are generated per HTML response.

- **Security Misconfiguration: secure session cookies, controlled CORS, and generic errors — PASS**
  - Session cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - CORS is only emitted for configured TLS localhost origins.
  - Runtime request failures return generic JSON error responses rather than stack traces.

- **Cryptographic Failures: secure secret generation and protection at rest — PASS**
  - TOTP secrets and recovery codes use `crypto.getRandomValues`.
  - TOTP secrets are protected with AES-GCM.
  - Recovery codes are normalized and stored as peppered SHA-256 hashes.
  - Secrets are not persisted in browser storage or client-readable cookies.

- **Cryptographic Failures: HTTPS enforcement — PASS**
  - The primary Bun server is configured with the required TLS certificate and key files.
  - The HTTP server redirects to the trusted HTTPS localhost origin.
  - HSTS is provided over application responses.

- **Injection: input validation, output safety, and redirect allow-listing — PASS**
  - Email, phone, OTP, and recovery-code input is normalized and validated server-side.
  - The only accepted redirect destination is `/`.
  - Dynamic UI values are placed with `textContent`; server-rendered HTML only interpolates a generated nonce.

- **Identification and Authentication: rate limiting, lockouts, session rotation/timeouts/logout — PASS**
  - Identity, TOTP, and backup-code failures are rate-limited and locked after five failures.
  - Sessions rotate after identity authentication.
  - Idle and absolute session timeouts are checked server-side.
  - Logout deletes the session and clears the cookie.

- **Identification and Authentication: verification codes are single-use and time-bound — FAIL**
  - The identity-code and TOTP verification paths contain asynchronous race conditions.
  - Concurrent requests using the same valid code can both pass validation before `identityUsed` or `acceptedTotpCounters` is updated.
  - This means a code is not guaranteed to be single-use under concurrent requests.

## FAILING_ITEMS

- **Identity verification code can be accepted more than once concurrently.**
  - In `/api/auth/identity`, `session.identityUsed` is checked before awaiting `protectedHash(code)`.
  - Two concurrent requests can both observe `identityUsed === false`, await hashing, then both proceed to mark the code used and rotate into separate authenticated sessions.

- **TOTP code can be accepted more than once concurrently.**
  - In `/api/mfa/verify`, `auth.user.acceptedTotpCounters.has(counter)` is checked before awaiting `totpForCounter(secret, counter)`.
  - Two concurrent requests can both observe that the counter is unused, await the HMAC calculation, then both accept and record the same counter.
  - Each successful concurrent request can also generate a different recovery-code set, causing one returned set to be replaced immediately by the other.

## NEW_TASKS

1. **Make identity-code consumption atomic.**
   - In `/api/auth/identity`, perform the asynchronous hash comparison first.
   - Immediately after it resolves, re-check `session.identityUsed`, expiry, lock status, and session stage.
   - Set `session.identityUsed = true` synchronously before performing any further `await` or session/user operations.
   - Reject the request if the code was already reserved or consumed by a concurrent request.

2. **Make TOTP counter consumption atomic.**
   - In `/api/mfa/verify`, calculate candidate TOTP values first, then re-check `acceptedTotpCounters` immediately before accepting a matching counter.
   - Add the accepted counter synchronously before any later asynchronous work, including recovery-code hashing/generation.
   - Reject concurrent verification attempts that find the counter already recorded.

3. **Prevent concurrent successful TOTP verification from producing conflicting recovery-code sets.**
   - After atomically reserving the accepted TOTP counter, ensure only the request that reserved it may set `mfaEnabled` and generate/store recovery codes.
   - Concurrent requests using the same TOTP must receive a generic failed-verification response rather than a second recovery-code response.

## DECISION

**FAIL**