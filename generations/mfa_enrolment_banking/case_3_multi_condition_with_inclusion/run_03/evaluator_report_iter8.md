## SUMMARY

The artifact is a single `app.ts` Bun application with inline HTML, CSS, and vanilla browser JavaScript. It provides a responsive MFA enrolment flow, TLS, secure headers, session cookies, CSRF checks, simulated identity OTPs, TOTP setup, and recovery codes. However, it does not fully meet the requirements because the displayed “QR code” is not a valid scannable QR code, recovery-code endpoints can be used before MFA enrolment is complete, recovery codes are not time-bound, and authenticator lockout can be bypassed by resetting setup details.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no framework, bundler, compiler, or external assets**
  - The entire server, HTML, CSS, and client-side JavaScript are contained in `app.ts`.
  - It uses `Bun.serve`, inline assets, and no external network resources.

- **PASS — TLS is configured using the required certificate paths**
  - The server reads `certs/cert.pem` and `certs/key.pem` and passes them to `Bun.serve({ tls: ... })`.

- **PASS — Responsive, mobile-oriented, dyslexia-aware interface**
  - The page includes a mobile viewport meta tag, constrained mobile-width layout, readable default font sizing, increased letter spacing, clear spacing, plain-language copy, input examples, and no animations or auto-updating components.
  - The step indicator and primary action are consistently prominent.

- **PASS — Sign-in, identity-code request, identity-code verification, authenticator setup, TOTP verification, recovery-code display, and completion flow are implemented**
  - The main happy path functions through browser API calls.
  - The mock identity code, authenticator secret/provisioning URI, mock TOTP, and recovery codes are returned to the UI and logged in the browser in academic mock mode.

- **PASS — Manual authenticator setup and clipboard support are present**
  - The authenticator secret and provisioning URI are shown in copyable controls.
  - Copy-to-clipboard actions are implemented with a usable fallback message.
  - OTP inputs use `autocomplete="one-time-code"` and numeric input modes.

- **FAIL — The offered QR code is not a real QR code**
  - `drawQr()` draws a pseudo-random grid with finder-like patterns, not a standards-compliant QR encoding of `provisioningUri`.
  - An authenticator application cannot scan this canvas to provision the TOTP secret.
  - This fails the requirement to offer a functioning QR-code provisioning option when one is presented.

- **PASS — Server-side account ownership is used for protected MFA actions**
  - Protected endpoints derive the user from the `mfa_session` server-side session rather than accepting a user ID from the client.
  - There is no user identifier input on MFA endpoints, reducing IDOR risk.

- **PASS — CSRF protections are applied to state-changing requests**
  - State-changing API calls require an `X-CSRF-Token`.
  - The sign-in bootstrap token is bound to the `mfa_boot` cookie, and authenticated actions use the session CSRF token.
  - Session cookies use `SameSite=Strict`.

- **PASS — Security headers and restrictive CORS are substantially implemented**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, and no-store cache headers are set.
  - CORS is only granted when the exact configured origin is supplied.

- **PASS — Session cookies use secure attributes and session expiry is enforced**
  - The session cookie is `Secure`, `HttpOnly`, and `SameSite=Strict`.
  - Server-side idle and absolute session timeouts are checked.
  - A new session ID is created at sign-in, mitigating session fixation.
  - A logout endpoint invalidates the server session and expires the cookie.

- **PASS — Secrets are not stored in browser storage**
  - The client does not use `localStorage`, `sessionStorage`, IndexedDB, or non-HttpOnly cookies for MFA secrets or session tokens.
  - TOTP seeds are encrypted in server memory and recovery codes are stored as hashes.

- **FAIL — Recovery-code endpoints are available before authenticator verification/MFA enablement**
  - `/api/recovery/regenerate` can be called by any authenticated session, including immediately after sign-in.
  - `/api/recovery/acknowledge` can also be called before authenticator enrolment.
  - This permits recovery-code generation and “completion” state changes outside the required enrolment order: identity verification → authenticator verification → recovery-code handling.
  - The server must enforce the workflow, not only the client UI.

- **FAIL — Recovery codes are single-use but not time-bound**
  - Recovery codes are removed after successful use, but the stored recovery hashes have no issuance or expiry timestamp.
  - The security requirements explicitly require verification codes/OTPs to be single-use and time-bound.
  - Add an expiry to recovery-code sets and reject expired recovery codes with a clear reissue action.

- **FAIL — Authenticator verification rate limiting can be bypassed**
  - After failed authenticator attempts, the client can call `/api/authenticator/setup`.
  - That endpoint calls `clearFailures(user.guards.auth)`, resetting failed-attempt counters and lockouts.
  - An attacker with an authenticated session can repeatedly reset setup details to avoid the intended five-attempt lockout.
  - Setup/reset operations must not clear a current lockout or failed-attempt counter.

- **FAIL — Sensitive mock values are additionally written into the visible in-page “Logs” panel**
  - `mockSensitiveLog()` calls both `console.log(...)` and `activity(...)`.
  - This causes mock OTPs, provisioning URIs, authenticator secrets, and recovery codes to be placed into the visible DOM log panel.
  - The requirements specifically require browser-console mock output for testing, but security requirements prohibit sensitive values in logs. Browser-console output can remain limited to academic mock mode; the on-page log must not contain sensitive values.

- **PASS — Input validation and output escaping are generally implemented**
  - Email, six-digit OTPs, and recovery-code format are validated server-side.
  - Client-rendered dynamic text uses `esc()` before insertion into `innerHTML`.
  - No redirect functionality is present, so there is no open redirect path.

- **PASS — Errors are generally specific, plain-language, and actionable**
  - Messages explain what failed and what the user should do, such as entering six digits, requesting a replacement code, or waiting after too many failed attempts.

## FAILING_ITEMS

- The canvas QR implementation is decorative/pseudo-random and cannot be scanned by standard authenticator applications.
- The server does not enforce the required MFA enrolment sequence for recovery-code generation, acknowledgement, or recovery verification.
- Recovery codes have no expiration mechanism, despite the time-bound verification-code requirement.
- Authenticator rate limiting is bypassable because `/api/authenticator/setup` clears authenticator failure and lockout state.
- Sensitive academic mock values are copied into the visible application “Logs” area in addition to the required browser console output.

## NEW_TASKS

1. Replace `drawQr()` with a standards-compliant, scannable QR-code encoder implemented inline in `app.ts`, encoding the exact `otpauth://` provisioning URI; retain the manual secret and copy controls.

2. Add server-side state guards to recovery endpoints:
   - Require `user.enabled === true` before `/api/recovery/regenerate`, `/api/recovery/acknowledge`, and `/api/recovery/verify`.
   - Require recovery codes to have been issued before acknowledgement or verification.
   - Return plain-language errors that direct the user to complete authenticator verification first.

3. Add an expiry timestamp to issued recovery-code sets:
   - Store a `recoveryExpiry` value on the user or store structured recovery-code records.
   - Reject recovery-code verification after expiry.
   - Require regeneration after expiration and clearly explain that the old set no longer works.

4. Preserve authenticator rate-limit state during authenticator setup/reset:
   - Do not call `clearFailures(user.guards.auth)` in `/api/authenticator/setup`.
   - If the authenticator guard is locked, reject setup/reset attempts until the lock period ends.
   - Only clear authenticator failures after successful `/api/authenticator/verify`.

5. Remove sensitive data from the visible `#logs` panel:
   - Keep required mock secrets/codes in `console.log` only when `ACADEMIC_MOCK_MODE` is enabled.
   - Ensure `activity()` receives only non-sensitive events such as “Authenticator details prepared” or “Recovery codes generated.”

## DECISION

FAIL