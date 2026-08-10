## SUMMARY

The artifact is a single-file Bun MFA SPA with a strong overall implementation: HTTPS/TLS, secure cookie attributes, CSRF checks, account-bound MFA records, CSP/security headers, encrypted OTP secrets, hashed recovery codes, validation, rate limiting, and a responsive accessible UI are largely present. However, it does not fully meet the security and simulation requirements because the default identity code is predictable, the test-mode authenticator OTP has no expiry, and deterministic recovery codes are reused after regeneration so old codes remain valid. The required comments mapping implementation to all requirement sections are also incomplete.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no framework/build tooling**
  - `app.ts` contains the Bun server, HTML template, CSS, and browser-side vanilla JavaScript.
  - It uses Bun directly and does not use bundlers, compilers, or external network assets.

- **PASS — TLS/HTTPS server using the specified certificate locations**
  - Bun is configured with `certs/cert.pem` and `certs/key.pem`.
  - The server serves HTTPS and attempts to redirect non-HTTPS requests.

- **PASS — Mobile-responsive, readable enrolment UI**
  - The layout has a narrow mobile-oriented shell (`max-width: 560px`), large form controls, generous spacing, plain-language text, step indicators, examples, help panels, and clearly visible primary actions.
  - No moving/flashing/auto-updating UI is present.

- **PASS — Manual authenticator setup and QR/copy options**
  - The provisioning screen provides a QR code, visible/manual secret field, copy-secret button, copy-URI button, reveal/hide option, and server-side validation of the manually supplied secret.
  - OTP entry can be completed manually.

- **PASS — Browser console simulation support in test mode**
  - When `MFA_TEST_MODE=1`, the server returns test secrets/codes to the UI and the browser script writes them using `console.log`.
  - Recovery codes and provisioning values are returned to the UI in test mode.

- **FAIL — Verification codes are sufficiently unpredictable and secure by default**
  - `SIMULATED_DELIVERY` defaults to enabled:
    ```ts
    const SIMULATED_DELIVERY = Bun.env.MFA_SIMULATED_DELIVERY !== "0";
    ```
  - With that default, `fixedOrRandomIdentityCode()` always returns `"123456"`:
    ```ts
    return SIMULATED_DELIVERY ? "123456" : secureText("0123456789", 6);
    ```
  - This is a predictable verification code and does not meet the requirement that verification codes have sufficient entropy. It is also returned to the browser response by default.

- **FAIL — Authenticator verification code is time-bound in test mode**
  - In `MFA_TEST_MODE`, `/api/otp/verify` accepts the fixed value `"654321"` without an expiry:
    ```ts
    if (TEST_ONLY) { if (equal(code, "654321")) used = -1; }
    ```
  - The code is single-use due to `usedTotpSteps`, but it is not time-bound. This fails the requirement that OTPs are both single-use and time-bound.

- **FAIL — Regenerating backup codes invalidates prior codes in all supported modes**
  - In normal mode, regeneration creates random replacement codes and invalidates the old hashes correctly.
  - In `MFA_TEST_MODE`, `recoveryCodes()` always returns the same `TEST_RECOVERY` array. Regeneration therefore creates hashes for the same values:
    ```ts
    if (TEST_ONLY) return [...TEST_RECOVERY];
    ```
  - After `/api/recovery/regenerate`, an old recovery code still matches the newly generated identical code set. This directly contradicts the UI message that “older codes no longer work.”

- **PASS — Server-side authorization and IDOR protection**
  - MFA records are bound to the authenticated server-side account ID.
  - Requests use the session account and do not accept client-controlled `userId` or `accountId`.
  - `ownedRecord()` verifies the expected authenticated account before MFA operations proceed.

- **PASS — CSRF protection on state-changing requests**
  - State-changing API calls require a session-bound CSRF token.
  - The client sends the token in JSON and the server validates it before processing MFA mutations, including provisioning, OTP verification, recovery-code use/regeneration, and logout.

- **PASS — Security headers, CORS restrictions, and secure session cookies**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, referrer policy, and no-store caching are present.
  - CORS is restricted to local trusted HTTPS origins.
  - Session cookies use `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, and a `__Host-` name.

- **PASS — Secrets are protected at rest and are not placed in browser storage**
  - OTP secrets are encrypted using AES-GCM.
  - Recovery codes are stored as PBKDF2-derived hashes with random salts.
  - No `localStorage`, `sessionStorage`, or non-HttpOnly cookie is used for secrets or session identifiers.

- **PASS — Input validation, output escaping, and open-redirect prevention**
  - JSON body parsing rejects account/user/redirect fields.
  - Email, password length, OTP, authenticator secret, and recovery-code formats are validated.
  - Dynamic client-rendered values are escaped before use in `innerHTML`.
  - No redirect parameter is accepted.

- **PASS — Rate limiting, lockouts, session rotation, expiry, and logout invalidation**
  - Login, identity-code, authenticator-code, and recovery-code failures have attempt counters and lockouts.
  - Sessions rotate after sign-in, expire on idle/absolute timeouts, and are deleted on logout.
  - Identity codes are marked used after successful verification.

- **FAIL — Clear comments mapping the implementation to all requirement sections**
  - There are a few useful comments, such as “Requirement 1/3” and “Requirement 5.”
  - However, the file does not provide clear, systematic comments mapping the major security, UX/inclusivity, cryptography, injection, and authentication requirements back to the implementation as requested.

## FAILING_ITEMS

- The default identity verification code is always `123456` when simulated delivery is enabled, which is the default configuration. This is predictable and fails the sufficient-entropy requirement for verification codes.
- The fixed test-mode authenticator code `654321` has no expiration window. It is single-use but not time-bound.
- Test-mode recovery-code regeneration reuses the exact same deterministic recovery-code list. As a result, codes described as “older codes” remain valid after regeneration.
- Comments do not clearly and comprehensively map code sections to the stated requirement sections.

## NEW_TASKS

1. Replace the default fixed identity code with a cryptographically random six-digit code; keep a deterministic identity code only in an explicit test-only mode such as `MFA_TEST_MODE=1`.
2. Add an expiry timestamp for the test-mode authenticator verification value, enforce that expiry in `/api/otp/verify`, and invalidate/reset the test OTP appropriately when provisioning is regenerated.
3. Change deterministic test recovery-code generation so each regeneration round returns a distinct deterministic set, ensuring every previously issued test recovery code fails after replacement.
4. Add concise comments throughout `app.ts` that explicitly map the relevant UI, authorization/CSRF, headers/TLS, cryptographic storage, validation/XSS, and authentication/rate-limit logic to Requirements 1–5 and the inclusivity requirements.

## DECISION

FAIL