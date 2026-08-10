## SUMMARY

The artifact is a single `app.ts` Bun application with inline HTML, CSS, and browser JavaScript. It has many strong elements: TLS configuration, security headers, HttpOnly/Secure/SameSite cookies, server-side CSRF checks, session rotation after identity verification, encrypted OTP secrets, hashed recovery codes, rate limiting, and a generally accessible mobile-oriented UI. However, it does not fully meet the requirements because the default enrolment flow cannot complete without test mode, the displayed QR code is not a real scannable QR code, the default “demo sign-in” grants access to Marcus’s account without authentication, and MFA state is globally shared and contains a completion-state flaw.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun implementation with no frameworks, bundlers, external assets, or external network calls.**
  - All server code, HTML, CSS, and client JavaScript are contained in `app.ts`.
  - The app uses Bun directly and only Node crypto APIs supplied through Bun compatibility.
  - No third-party libraries, build tooling, or external assets are used.

- **PASS — Bun server is configured for HTTPS using the required certificate paths.**
  - `Bun.serve` includes:
    ```ts
    tls: { cert: "certs/cert.pem", key: "certs/key.pem" }
    ```
  - The server advertises an HTTPS localhost URL.

- **PASS — Mobile responsive and dyslexia-aware presentation is largely implemented.**
  - The app has a mobile viewport meta tag and a constrained responsive `main` layout.
  - It uses generous spacing, 16–17px base text sizing, increased letter spacing, readable line height, plain-language instructions, short examples, icons, and no auto-updating or animated interface elements.
  - Each stage has a help disclosure and retry/restart option.
  - The UI avoids all-caps instructional text and italics.

- **PASS — Core MFA stages are represented and server-enforced in the intended order.**
  - The UI includes identity verification, authenticator provisioning, TOTP verification, backup-code generation, completion, and backup-code verification.
  - Server routes enforce identity verification before provisioning and OTP verification before backup generation.
  - Identity codes are time-bound and single-use.
  - TOTP counters are prevented from being accepted twice.
  - Recovery codes are removed after successful use.

- **FAIL — The normal local demo identity-verification flow is not completable.**
  - In default mode, `/api/identity/send` generates a random code but returns only `{ ok: true }`.
  - The browser logs only:
    ```js
    log("Simulated identity code delivery sent to phone ending in 4821.");
    ```
    and does not log or display the actual code.
  - Consequently, a user in the default local demo cannot know the random identity code required by `/api/identity/verify`.
  - The required simulated OTP delivery is therefore not functional unless `MFA_TEST_MODE=1` is manually enabled and the fixture flow is used.

- **FAIL — Mock OTP and backup values are not consistently returned and logged in the browser as required.**
  - The requirements explicitly require simulated mock values to be returned to the UI and shown via browser `console.log`.
  - In normal demo mode:
    - The identity OTP is not returned or logged.
    - The current authenticator OTP is not returned or logged.
    - Backup codes are returned to the UI but the actual code values are not logged; only a generic message is logged.
  - Actual values are exposed only in academic test mode.

- **FAIL — The QR-code option is not a valid provisioning QR code.**
  - The `qr(uri)` function creates a decorative pseudo-random SVG pattern derived from the provisioning URI hash.
  - It does not implement QR encoding, error correction, or a standards-compliant QR matrix.
  - Authenticator applications cannot reliably scan it, so the promised QR setup path is non-functional.
  - The manual setup-key route works, but it does not make the advertised QR option valid.

- **FAIL — Authentication/authorization is not sufficient for the default deployment.**
  - `/api/demo/login` creates an authenticated session for `ACCOUNT_ID` solely when a request supplies an allowed same-origin `Origin`:
    ```ts
    const session = createAuthenticatedSession(false, false);
    ```
  - It does not validate any credentials, signed identity assertion, prior authenticated session, or user identity.
  - Since `LOCAL_DEMO_ENABLED` defaults to enabled, anyone able to load the site can use “Open local demo setup” and obtain a session for Marcus’s account.
  - This violates the requirement that only the authenticated account owner may view or modify their MFA settings.
  - The signed `trustedOwnerAssertion` path is better, but the insecure demo path remains enabled by default.

- **FAIL — MFA data is held in one global record instead of account-scoped storage.**
  - All MFA state is stored in the single global `record`:
    ```ts
    const record: AccountMfa = { ... };
    ```
  - This includes the OTP secret, identity code, recovery-code hashes, lockout state, and MFA completion state.
  - Although the current implementation hard-codes one account ID, this architecture does not enforce account-scoped ownership and would leak/overwrite MFA state if expanded to more than one account.
  - It does not satisfy the stated requirement to enforce ownership for each account’s MFA settings.

- **FAIL — MFA completion can use stale recovery codes after a new provisioning attempt.**
  - `/api/provision` resets:
    ```ts
    record.otpVerified = false;
    record.mfaEnabled = false;
    ```
    but does not clear `record.recoveryHashes`.
  - `/api/complete` checks only that recovery hashes exist:
    ```ts
    if (!record.recoveryHashes.length) { ... }
    record.mfaEnabled = true;
    ```
  - Therefore, after a prior backup-code generation, a later provisioning attempt can be completed without verifying the newly provisioned authenticator, as long as old recovery hashes remain.
  - `/api/complete` must require `otpVerified`, and re-provisioning should invalidate stale recovery codes.

- **PASS — CSRF protection is applied to protected state-changing MFA routes.**
  - Protected POST routes require both a live owner session and a matching `X-CSRF-Token`.
  - The request `Origin` must match a trusted HTTPS localhost origin.
  - Cookies are `SameSite=Strict`, adding defense in depth.

- **PASS — Session controls are substantially implemented.**
  - Session cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - Sessions have idle and absolute expiry checks.
  - The session ID is rotated after successful identity verification.
  - Logout deletes the server session and expires the cookie.

- **PASS — Security response headers and basic CORS restrictions are implemented.**
  - CSP with nonces is present for HTML responses.
  - HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, and `Cache-Control: no-store` are set.
  - OPTIONS CORS handling restricts origins to the configured HTTPS localhost allow-list.
  - Errors are generic and do not expose stack traces.

- **PASS — Sensitive material uses suitable cryptographic primitives in the normal flow.**
  - OTP secrets are encrypted using AES-256-GCM.
  - Recovery codes are generated with `randomBytes` in non-fixture mode and stored as salted `scrypt` hashes.
  - Session IDs and CSRF tokens use cryptographically secure random values.
  - OTP verification uses timing-safe comparisons.

- **PASS — Input validation and output escaping are generally sound.**
  - Phone suffixes, six-digit OTPs, and recovery-code format are validated server-side.
  - Dynamic UI values are escaped before use in `innerHTML`, or inserted via `textContent`.
  - There are no user-controlled redirects or database queries.

## FAILING_ITEMS

- The default local demo creates an authenticated Marcus session without validating user credentials or an authenticated upstream assertion.
- The default identity OTP is random but never returned to the UI or browser console, making the normal flow impossible to complete.
- Default simulated authenticator OTPs and actual recovery-code values are not consistently returned/logged in the browser as required for testing.
- The SVG “QR code” is not a real QR code and cannot be relied upon for authenticator provisioning.
- MFA state is globally stored in one `record` rather than being scoped to the authenticated account.
- Re-provisioning does not clear old recovery codes.
- `/api/complete` does not require successful verification of the currently provisioned authenticator.

## NEW_TASKS

1. Disable `/api/demo/login` by default and require a validated upstream signed identity assertion or a clearly isolated, explicitly enabled test-only authentication mode before creating an authenticated MFA session.

2. Make the simulated identity-verification delivery functional in the enabled demo/test mode: return a deterministic test code and log that exact code through browser `console.log`; do not require manual access to server memory or logs.

3. Ensure all required simulated testing values are returned to the browser and logged via browser `console.log`, including identity OTPs, authenticator test OTPs, and generated backup recovery codes. Keep production/server logs free of secrets.

4. Replace `qr(uri)` with an actual standards-compliant QR-code encoder that produces a scannable QR code for the exact `otpauth://` provisioning URI, while retaining the manual copyable setup-key option.

5. Replace the global MFA `record` with MFA records keyed by authenticated `accountId`, and ensure every MFA read/write operation uses the owner session’s account record.

6. On `/api/provision`, clear existing recovery-code hashes and any stale completion state for that account.

7. On `/api/complete`, require both a verified authenticator (`otpVerified`) and newly generated recovery codes for the current enrolment before setting `mfaEnabled`.

## DECISION

FAIL