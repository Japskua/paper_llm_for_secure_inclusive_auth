## SUMMARY

The artifact is a strong single-file Bun MFA enrolment prototype with a responsive mobile UI, TLS-only server, authenticated session handling, CSRF tokens, encrypted TOTP secrets, hashed recovery codes, and working simulated enrolment/verification flows. However, it does not fully meet the security requirements because several lockouts can be bypassed by restarting/resetting the related flow, authentication timing can reveal account-match information, and the OTP setup secret is logged in the browser despite the requirement not to expose OTP seeds in logs.

## FUNCTIONAL_CHECK

- **PASS — Single-file app.ts / zero-compilation compliance**
  - The Bun server, HTML, CSS, and vanilla browser JavaScript are all contained in `app.ts`.
  - No framework, bundler, compiler, external assets, database, or external network calls are used.

- **PASS — HTTPS/TLS enforcement**
  - Startup refuses to run unless `certs/cert.pem` and `certs/key.pem` exist.
  - `Bun.serve` is configured with TLS and the application does not provide an HTTP fallback.
  - HSTS is sent with `Strict-Transport-Security`.

- **PASS — Responsive mobile SPA UI**
  - The page includes a mobile viewport meta tag and uses a constrained, responsive mobile layout.
  - Forms, buttons, focus states, OTP inputs, recovery-code display, and narrow-screen CSS are implemented.
  - The enrolment flow is legible and usable at phone-sized widths.

- **PASS — Functional MFA enrolment flow**
  - The UI supports sign-in details, identity-code verification, authenticator setup, manual setup-secret entry, TOTP confirmation, recovery-code display, confirmation, settings, recovery-code verification, regeneration, and logout.
  - TOTP generation and verification are implemented server-side and the displayed test OTP can successfully confirm enrolment.
  - Recovery codes can be verified once and are removed after successful use.

- **PASS — Manual authenticator provisioning support**
  - A Base32 authenticator secret is displayed in the UI for manual entry into an authenticator app.
  - A QR code is not offered, so there is no unmet QR-code submission requirement.

- **PASS — Browser-side simulation outputs**
  - Identity verification codes, test authenticator codes, and backup recovery codes are returned to the authenticated UI and logged with browser `console.log`.
  - The Bun server itself does not log these values.

- **PASS — Server-side MFA authorization / IDOR prevention**
  - MFA routes derive the account owner from the HttpOnly server-side session via `authenticatedOwner`.
  - Client-provided ownership fields (`userId`, `accountId`, `ownerId`, and `email`) are rejected on MFA state-changing routes.
  - MFA records are accessed only through the authenticated account identity, not a user identifier supplied by the request.

- **PASS — CSRF protections on authenticated state-changing MFA endpoints**
  - MFA setup, confirmation, recovery verification, backup-code regeneration, and logout require the per-session `X-CSRF-Token`.
  - Session cookies use `SameSite=Strict`, further reducing cross-site request risk.
  - The initial sign-in start flow does not use a CSRF token, but does not modify an authenticated account’s MFA state.

- **PASS — Secure session-cookie attributes and session lifecycle**
  - The session cookie is `HttpOnly`, `Secure`, `SameSite=Strict`, path-scoped to `/`, and uses the `__Host-` prefix.
  - The server rotates the session identifier after successful identity verification.
  - Idle and absolute server-side session expiry are implemented.
  - Logout invalidates the server-side session and expires the browser cookie.

- **PASS — Security response headers and CORS restriction**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, no-referrer policy, no-store caching, and a restrictive permissions policy are present.
  - CORS only emits `Access-Control-Allow-Origin` for HTTPS loopback origins on the configured port.

- **PASS — Cryptographic protection at rest**
  - TOTP secrets are generated with `crypto.getRandomValues` and encrypted using AES-GCM before server-side storage.
  - Recovery codes are generated with cryptographic randomness and stored as keyed HMAC-SHA-256 values rather than plaintext.
  - No session tokens or MFA secrets are stored in `localStorage`, `sessionStorage`, or client-readable cookies.

- **PASS — Input validation and output handling**
  - Email, phone numbers, OTPs, and backup codes are format-validated server-side.
  - JSON bodies are type-checked and size-limited.
  - User-controlled data is not rendered through unsafe `innerHTML`; dynamic values are assigned with `textContent`.
  - There are no redirect parameters or externally controlled redirects.

- **FAIL — Failed-verification lockouts are bypassable**
  - Identity-code lockout is stored only in the pre-auth session. A client can call `/api/auth/start` again to obtain a fresh pre-auth session and reset the five-attempt counter.
  - Authenticator-confirmation lockout is stored only in the pending enrolment. An authenticated user can call `/api/mfa/setup` again and replace the locked enrolment with a fresh one.
  - Recovery-code lockout is reset by `/api/mfa/backup/regenerate`, because regeneration sets `recoveryAttempts = 0` and clears `recoveryLockedUntil`.
  - This does not satisfy the requirement to rate-limit and lock out repeated failed verification attempts.

- **FAIL — Account-match timing is distinguishable during identity verification**
  - The identity verification expression short-circuits:
    `session.userId === ACCOUNT.id && secureEquals(...)`.
  - For an unrecognised email/phone combination, the OTP comparison is skipped; for the account owner it is performed.
  - This creates a measurable timing difference and conflicts with the requirement to avoid account/user enumeration in response timing.

- **FAIL — OTP shared secret is exposed in browser logs**
  - `renderEnroll()` calls:
    `mockLog("Simulated authenticator setup secret", data.manualSecret)`.
  - `mockLog` writes the OTP seed to both `console.log` and the visible on-page Logs panel.
  - The manual secret must be shown in the provisioning UI so it can be entered into an authenticator, but it should not be logged. This violates the requirement not to expose OTP seeds in logs.

- **PASS — Production-style generic error handling**
  - The outer request handler catches exceptions and returns a generic JSON error response.
  - Stack traces and internal crypto/storage errors are not sent to the browser.

## FAILING_ITEMS

- Verification lockouts are not durable enough to prevent repeated attempts:
  - Restarting `/api/auth/start` resets identity-verification attempts.
  - Restarting `/api/mfa/setup` resets authenticator-confirmation attempts.
  - Regenerating backup codes clears recovery-code lockout and attempt counters.
- Identity verification has an account-dependent timing difference because OTP comparison occurs only when `session.userId === ACCOUNT.id`.
- The TOTP provisioning secret is written to the browser console and visible Logs panel.

## NEW_TASKS

1. Add a server-side, account- and/or client-rate-based verification throttle that persists across replacement pre-auth sessions, setup restarts, and recovery-code regeneration; enforce it for identity OTP, authenticator OTP, and recovery-code failures.
2. Prevent `/api/mfa/setup` from resetting a currently locked enrolment attempt state, or store MFA setup failure counters and lock state separately from the replaceable pending-enrolment object.
3. Do not clear recovery verification attempts or `recoveryLockedUntil` when backup codes are regenerated; only reset the counter after a successful recovery-code verification or after the lock duration expires.
4. Refactor identity-code verification so recognized and unrecognized account details perform equivalent constant-time OTP work before returning the same generic response.
5. Remove `mockLog("Simulated authenticator setup secret", data.manualSecret)` and ensure the manual secret is only displayed in the protected provisioning UI, not written to browser console or the visible Logs panel.

## DECISION

FAIL