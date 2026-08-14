## SUMMARY

The artifact is a single-file Bun HTTPS application with a functional, mobile-responsive MFA enrolment flow. It implements session ownership checks, CSRF tokens, secure cookies, TLS, security headers, encrypted TOTP-secret storage, hashed recovery codes, browser-only simulation logging, and working enrolment/recovery flows. However, repeated malformed verification submissions do not contribute to lockout counters, so the required repeated-failure rate limiting and lockout is incomplete.

## FUNCTIONAL_CHECK

- **Single `app.ts` artifact containing Bun server, HTML, CSS, and vanilla client JavaScript — PASS**
  - The server and complete SPA template are contained in one file.
  - No framework, bundler, external asset, external API call, or separate client build is used.

- **Bun HTTPS server uses provided TLS certificate paths — PASS**
  - The server checks for `certs/cert.pem` and `certs/key.pem`.
  - `Bun.serve` is configured with `tls: { cert, key }`.
  - Startup fails safely if certificates are absent.

- **Mobile-responsive and legible UI — PASS**
  - The viewport meta tag is present.
  - Layout is constrained to a mobile-friendly maximum width.
  - Inputs and buttons have appropriate touch-friendly minimum heights.
  - A narrow viewport media query is included.

- **MFA enrolment flow works end-to-end — PASS**
  - Users can start identity verification, submit the simulated identity code, provision a TOTP secret manually, confirm the authenticator, view recovery codes, and reach security settings.
  - The manual authenticator secret is displayed in the UI.
  - The simulated current TOTP is shown in the browser console and visible browser log panel.
  - Backup codes are shown after enrolment and logged in the browser.

- **Recovery-code verification and regeneration work — PASS**
  - Recovery codes are generated with `crypto.getRandomValues`.
  - Stored recovery codes are HMAC-hashed rather than retained in plaintext.
  - A successfully used recovery code is removed and cannot be reused.
  - Regenerating codes replaces old hashes.
  - Recovery-code failures have a lockout mechanism.

- **Server-side MFA authorization / IDOR protection — PASS**
  - MFA endpoints derive the account owner from the authenticated HttpOnly session through `owner(request)`.
  - The client cannot select another user via `userId`, `accountId`, or `ownerId`.
  - MFA routes reject manipulated ownership fields.

- **CSRF protection for authenticated state-changing MFA requests — PASS**
  - State-changing authenticated routes require `X-CSRF-Token`.
  - CSRF tokens are server-generated, session-bound, and rotated when authentication rotates the session.
  - The session cookie uses `SameSite=Strict`.

- **Session security — PASS**
  - Session cookies are `HttpOnly`, `Secure`, `SameSite=Strict`, and scoped with `Path=/`.
  - The `__Host-` cookie naming requirements are respected.
  - Sessions have idle and absolute expiry handling.
  - The session is rotated after successful identity verification.
  - Logout invalidates the session and expires the cookie.

- **Secure headers and CORS restriction — PASS**
  - CSP with nonce-based script and style execution is present.
  - HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, referrer policy, cache control, and permissions policy are configured.
  - CORS allows only HTTPS origins on configured localhost hosts and port 3000.

- **Secret handling and cryptography — PASS**
  - TOTP secrets are generated using cryptographically secure randomness.
  - TOTP secrets are encrypted with AES-GCM before server-side storage.
  - Backup codes are stored as keyed HMAC hashes.
  - Session tokens and secrets are not placed in URL query strings or browser storage.
  - Server logs do not log OTP secrets, OTPs, recovery codes, or session identifiers.
  - Required mock values are logged in the browser only.

- **Input validation and output encoding — PASS**
  - JSON request bodies are size-limited and parsed safely.
  - Email, phone, OTP, and recovery-code input formats are validated server-side.
  - DOM output of dynamic values uses `textContent`, avoiding DOM XSS.
  - There is no redirect functionality that could create an open redirect.

- **Single-use and time-bound verification values — PASS**
  - Identity codes have an expiry.
  - Pending enrolment secrets expire.
  - TOTP confirmation rejects previously used TOTP counters.
  - Recovery codes are single-use.

- **Rate limiting and lockout of repeated failed verification attempts — FAIL**
  - Validly formatted incorrect six-digit OTPs and recovery codes increment lockout counters.
  - However, malformed OTPs, malformed recovery codes, missing values, and invalid-format verification submissions are rejected before the relevant throttle is retrieved or incremented.
  - An attacker can repeatedly submit invalid-format values without reaching the five-failure lockout threshold, which does not satisfy the requirement to rate-limit and lock out repeated failed verification attempts.

- **No verbose production errors / account enumeration resistance — PASS**
  - Errors return generic messages.
  - The request handler suppresses stack traces.
  - Authentication start returns a generic success response shape for recognized and unrecognized details.
  - Verification performs a constant-time comparison for the code candidate before the final generic decision.

## FAILING_ITEMS

- **Malformed verification attempts bypass all verification lockouts.**
  - `/api/auth/verify` returns before loading and incrementing `identityThrottles` when `validOtp(input.code)` is false.
  - `/api/mfa/confirm` returns before loading and incrementing `authenticatorThrottles` when `validOtp(input.otp)` is false.
  - `/api/mfa/recovery/verify` returns before loading and incrementing the recovery-code failure counter when `validBackup(input.code)` is false.
  - Consequently, repeated invalid-format attempts can continue indefinitely without lockout.

## NEW_TASKS

1. **Count malformed identity-code submissions as failed identity-verification attempts.**
   - In `/api/auth/verify`, validate the session and CSRF token first.
   - Retrieve and check the relevant identity throttle before returning for an invalid or missing OTP format.
   - Increment the throttle for invalid-format, expired, or incorrect identity-code submissions.

2. **Count malformed authenticator-code submissions as failed authenticator-verification attempts.**
   - In `/api/mfa/confirm`, validate ownership and CSRF first.
   - Retrieve and check `authenticatorThrottles` before rejecting invalid or missing OTP format.
   - Increment the throttle for invalid-format, expired, reused, or incorrect authenticator-code submissions.

3. **Count malformed recovery-code submissions as failed recovery-code attempts.**
   - In `/api/mfa/recovery/verify`, validate ownership and CSRF first, retrieve the MFA record and refresh/check its lock state, then count invalid-format or incorrect recovery-code submissions as failures.
   - Preserve the existing lock duration and reset behavior after successful recovery-code use.

## DECISION

FAIL