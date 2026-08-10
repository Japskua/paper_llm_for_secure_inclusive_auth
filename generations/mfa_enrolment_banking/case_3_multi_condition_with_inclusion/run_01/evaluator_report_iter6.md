## SUMMARY

The artifact is a strong single-file Bun HTTPS MFA enrolment SPA with responsive mobile UI, accessible plain-language flow, server-side session ownership checks, CSRF checks, secure headers, TOTP generation/verification, and encrypted OTP seed storage. However, it does not fully meet the security and recovery-code requirements: recovery codes are generated and hashed but cannot be verified/consumed, lockout state does not reset after expiry, and sensitive mock values are also rendered into an on-page log area.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no framework/build tooling**
  - The complete Bun server, HTML, CSS, and browser JavaScript are contained in `app.ts`.
  - It uses `Bun.serve` directly and does not depend on external packages, external assets, bundlers, or compilers.

- **PASS — HTTPS/TLS server configuration**
  - `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`.
  - Requests are rejected unless they use HTTPS and a trusted localhost host value.

- **PASS — Mobile-friendly, dyslexia-conscious enrolment UI**
  - The UI is responsive, has a mobile viewport meta tag, readable font sizing, generous spacing, plain-language instructions, visible progress steps, examples for email/OTP input, and clear primary actions.
  - It avoids timers, animations, flashing elements, dense copy, and all-caps instructional text.
  - Help is available on each screen through the consistently placed `<details>` section.

- **PASS — Authenticator provisioning supports QR and manual entry**
  - The server generates a cryptographically random Base32 TOTP secret.
  - The client renders a QR code and displays a manually copyable secret.
  - The user can hide/reveal the secret, copy it, and request a new setup.

- **PASS — TOTP verification works and is protected**
  - OTPs are validated server-side as six digits.
  - The OTP seed is AES-GCM encrypted at rest in the server-side account object.
  - TOTP verification accepts only valid time-window codes and tracks accepted TOTP counters to prevent replay.
  - Failed OTP attempts are rate-limited and locked after five failures.

- **FAIL — Recovery codes cannot actually be used or consumed**
  - Recovery codes are generated and stored as keyed HMAC verifiers, which is good.
  - However, there is no endpoint or UI flow to submit a recovery code, compare it with stored verifiers, consume it after use, or exercise `recoveryFailedAttempts` / `recoveryLockedUntil`.
  - As implemented, recovery codes are only displayed and regenerated; they do not function as recovery authentication factors.

- **FAIL — Lockout does not properly reset after the lock period**
  - When OTP verification reaches `MAX_FAILURES`, `otpLockedUntil` is set, but `otpFailedAttempts` remains at `5`.
  - After the five-minute lock expires, the next failed attempt immediately causes another lock because `otpFailedAttempts >= MAX_FAILURES` is still true.
  - This conflicts with the message telling the user to wait and retry, and with the requirement to let users retry without unfair penalty.

- **PASS — Authorization and IDOR protection**
  - Protected MFA actions derive the account entirely from the signed session.
  - No endpoint accepts a user/account identifier from the client.
  - Manipulating an account identifier is therefore not possible through the exposed MFA APIs.

- **PASS — CSRF protection for state-changing actions**
  - State-changing authenticated endpoints require both a session and a matching `X-CSRF-Token`.
  - The request origin must match the HTTPS same-origin trusted localhost origin.
  - Cookies are `SameSite=Strict`, adding further CSRF mitigation.

- **PASS — Session security**
  - Sessions use cryptographically random tokens.
  - Session cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - Sessions have idle and absolute expiration.
  - Existing sessions for the account are invalidated at sign-in, mitigating session fixation and concurrent stale sessions.
  - Logout invalidates the session and expires the cookie.

- **PASS — Security response headers and CORS restrictions**
  - CSP with nonce-based script/style policy, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, restrictive referrer policy, and no-store caching are implemented.
  - CORS is only enabled for the exact same trusted local origin.

- **FAIL — Sensitive OTP and recovery-code data is rendered into an on-page “Logs” panel**
  - `getSetup()` calls `log("Mock authenticator setup delivered. Testing code: "+mockOtp)`.
  - `verifyOtp()` calls `log("Generated recovery-code array: "+currentCodes.join(", "))`.
  - The `log()` function writes these values into visible DOM content in `#logList`, creating an application-visible sensitive-data log.
  - The testing requirement requires browser `console.log` output for mocks, but it does not require displaying OTPs and recovery codes in a separate on-page log. The visible log panel unnecessarily broadens exposure and conflicts with the requirement not to expose OTPs or backup codes in logs.

- **PASS — Input validation and output encoding**
  - JSON requests are required and parsed defensively.
  - Email, password, OTP, and recovery-code formats have server-side validation functions.
  - User-derived rendered values are escaped with `esc()` before insertion into HTML.
  - No SQL/database queries are used, so there is no unparameterized SQL injection path.

- **PASS — Generic server error handling**
  - The top-level server handler catches exceptions and returns a generic message.
  - It does not expose stack traces or debug details.

## FAILING_ITEMS

- Recovery codes are not functional recovery credentials because there is no recovery-code verification/consumption endpoint or UI.
- Recovery-code lockout fields exist but are unused, so failed recovery-code attempts are not rate-limited.
- OTP lockout attempts are not reset after `otpLockedUntil` expires; a single subsequent failed attempt immediately re-locks the user.
- OTP test values and recovery codes are copied into the visible in-page `Logs` list, unnecessarily exposing sensitive values beyond the required browser-console testing output.

## NEW_TASKS

1. Add a server-side recovery-code verification endpoint that:
   - Requires the authenticated session and CSRF protection consistent with the stated access-control requirement.
   - Validates recovery-code format.
   - Compares submitted codes against stored HMAC verifiers using constant-time comparison.
   - Removes the matched verifier after successful use so the recovery code is single-use.
   - Applies and resets `recoveryFailedAttempts` and `recoveryLockedUntil`.

2. Add a recovery-code entry screen or authenticated recovery-code test/verification flow in the client so generated recovery codes can actually be submitted and verified.

3. Reset OTP failure state when an OTP lock has expired:
   - Before evaluating a new OTP attempt, if `otpLockedUntil <= now`, set `otpFailedAttempts = 0` and `otpLockedUntil = 0`.
   - Apply the same expiry-reset logic to recovery-code lockout state when implementing recovery-code verification.

4. Remove the visible `#logList` / `.logs` sensitive-data panel, or ensure it never receives OTPs, secrets, session-related data, or recovery codes.
   - Retain only the browser `console.log` calls explicitly required for testing mocks.
   - Do not render test OTPs or recovery-code arrays into a general-purpose page log.

## DECISION

**FAIL**