## SUMMARY

The artifact is a well-structured single-file Bun HTTPS MFA enrolment SPA with server-side session ownership, CSRF checks for authenticated MFA changes, encrypted TOTP secrets, hashed recovery codes, rate limiting, mobile UI, and browser-only test mock logging. However, it does not provide a usable authenticator provisioning path in production mode, so real TOTP confirmation cannot work. Its CSP also permits unrestricted inline scripts/styles via `'unsafe-inline'`, which weakens the stated XSS/security-header protection requirement.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun server and SPA delivery**
  - The server, HTML, CSS, and vanilla browser JavaScript are contained in `app.ts`.
  - It uses `Bun.serve` directly, with no framework, bundler, external assets, or compilation step.
  - It reads the specified TLS certificate and key paths and serves HTTPS.

- **PASS — Responsive, mobile-oriented, semantic enrolment UI**
  - The UI uses semantic elements including `main`, `header`, `section`, `form`, `label`, `button`, and heading hierarchy.
  - Layout is constrained to a mobile-friendly maximum width and includes a narrow-screen media query.
  - Inputs use suitable mobile attributes such as `inputmode`, `autocomplete`, and appropriate input types.

- **PASS — Browser-side mock logging and test flow**
  - In test mode, identity codes, provisioning secrets/current TOTP values, and recovery codes are displayed in the UI where applicable and logged through browser `console.log`.
  - The server does not log the sensitive mock values.
  - The test-mode manual authenticator secret enables deterministic testing of TOTP setup.

- **PASS — Server-side MFA authorization / IDOR prevention**
  - MFA endpoints derive the account only from the authenticated server-side session.
  - No MFA API accepts a user/account identifier that could be manipulated to access another account’s settings.
  - Session ownership is checked before MFA status, enrolment, confirmation, recovery-code use, regeneration, and logout actions.

- **PASS — CSRF protections for authenticated MFA state changes**
  - Authenticated state-changing MFA endpoints require an `X-CSRF-Token` matching the server-side session token.
  - Session cookies use `SameSite=Strict`, which provides additional cross-site request protection.
  - Logout, enrolment, confirmation, recovery-code use, and recovery-code regeneration are CSRF-protected.

- **FAIL — Secure CSP configuration**
  - The application sends CSP and clickjacking headers, but the CSP includes `script-src 'unsafe-inline'` and `style-src 'unsafe-inline'`.
  - Allowing unrestricted inline scripts substantially reduces CSP’s ability to mitigate injected script execution. This does not satisfy the intent of a secure CSP/XSS defense.
  - The inline script and stylesheet should instead be authorized using a per-response nonce or CSP hashes.

- **PASS — Other required security headers and CORS restrictions**
  - Responses include HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, `Permissions-Policy`, and `Cache-Control: no-store`.
  - CORS response headers are emitted only for the explicitly trusted localhost HTTPS origins.
  - Untrusted explicit `Origin` headers are rejected.

- **PASS — Secure session cookie and session lifecycle handling**
  - Session cookies are `HttpOnly`, `Secure`, `SameSite=Strict`, and scoped to `/`.
  - The authenticated session is regenerated after identity verification, mitigating session fixation.
  - Idle and absolute server-side session expiration are enforced.
  - Logout removes the server session and expires the session cookie.

- **PASS — Cryptographic generation and storage**
  - TOTP secrets and tokens use `crypto.getRandomValues`.
  - TOTP secrets are encrypted using AES-GCM before being retained in MFA records.
  - Recovery codes are stored as HMAC-SHA-256 values with a server-side pepper rather than plaintext.
  - Recovery codes are invalidated after use and prior codes are replaced on regeneration.

- **PASS — TOTP and recovery-code verification controls**
  - TOTP follows an RFC-6238-style HMAC-SHA-1 calculation with a 30-second period.
  - Accepted setup TOTP counters are recorded to prevent reuse during enrolment.
  - Recovery codes are one-time values.
  - Failed identity, authenticator, and recovery-code attempts are rate-limited with a lockout after five failures.

- **PASS — Input validation and output encoding**
  - Email, phone, OTP, and recovery-code formats are validated server-side.
  - Dynamic client-side values are placed through `textContent` and DOM node construction rather than unsafe HTML insertion.
  - There is no SQL/database layer; therefore parameterized SQL queries are not applicable to the in-memory mock registry.

- **FAIL — Production authenticator provisioning and verification flow**
  - When `NODE_ENV=production`, `/api/mfa/enrol` deliberately returns neither the TOTP secret nor an `otpauth://` provisioning URI/QR payload.
  - The production UI then hides the manual setup key and only tells the user to follow unspecified bank instructions.
  - As a result, a real authenticator app has no secret/URI from which to generate a valid six-digit code. The user can only guess a valid TOTP, so production enrolment verification is not functional.
  - This violates the requirement that the MFA enrolment and verification flow work, including manual provisioning where relevant.

- **PASS — Internal navigation and SPA interactions**
  - Sign-in, identity verification, MFA setup, cancellation, recovery-code display, recovery-code use, regeneration, return-to-settings, and logout controls are wired to functioning handlers.
  - The SPA does not rely on broken internal URLs or external navigation.

## FAILING_ITEMS

- The CSP permits unrestricted inline script and style execution through `'unsafe-inline'`. This weakens the required CSP/XSS defense and is avoidable in a single-file application.
- Production MFA setup is unusable: the app does not provide an authenticator provisioning secret, QR payload, or `otpauth://` URI to the authenticated user, yet expects that user to submit a TOTP derived from that undisclosed secret.

## NEW_TASKS

1. Replace CSP `'unsafe-inline'` allowances with a per-response nonce or CSP hashes, and apply the nonce to the inline `<script>` and `<style>` elements.
2. Implement a secure production provisioning response for authenticated enrolment: return/render a manual TOTP secret and/or standard `otpauth://` URI only in the protected HTTPS response/UI, never in URLs, server logs, browser logs, storage, or error messages.
3. Ensure the production setup UI visibly presents the provisioning material and clear manual authenticator instructions before requesting the six-digit authenticator code.

## DECISION

FAIL