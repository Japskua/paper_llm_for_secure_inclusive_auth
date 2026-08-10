## SUMMARY

The artifact is a single-file Bun HTTPS SPA with a clear mobile-oriented MFA enrolment UI, CSRF checks, security headers, session cookies, input validation, and simulated code delivery. However, it does not meet several core functional and security requirements: the authenticator flow is not actually time-based or tied to the shown setup secret/QR code, the QR code is decorative rather than scannable, authentication/ownership is effectively bypassable, rate limiting can be bypassed, and backup-code protection is weak. Therefore, the artifact cannot be accepted as-is.

## FUNCTIONAL_CHECK

- **FAIL — Single-file Bun application with inline HTML, CSS, JS, and server logic**
  - `app.ts` does contain the Bun server and the full HTML/CSS/client JavaScript template in one file.
  - However, the functional and security defects below prevent overall acceptance.

- **PASS — HTTPS/TLS server configuration**
  - Bun is configured with `certs/cert.pem` and `certs/key.pem`.
  - The application uses `Secure` cookies and includes HSTS.

- **PASS — Mobile-responsive, dyslexia-conscious presentation**
  - The UI has a constrained mobile width, large controls, legible font sizing, ample spacing, plain wording, short hints/examples, icons, non-moving content, and a visible step indicator.
  - Inputs include mobile-friendly `inputmode`, browser autofill hints, and `autocomplete="one-time-code"` where appropriate.

- **PASS — Clear progressive MFA enrolment flow**
  - The flow has sign-in, identity check, authenticator provisioning, authenticator-code verification, backup-code generation, completion, and logout screens.
  - The primary action is generally clear on each step and errors give corrective guidance.

- **PARTIAL/FAIL — Simulated MFA codes are shown in the browser console**
  - Identity, authenticator, setup-secret, and backup-code values are emitted with browser-side `console.log`, as required for testing.
  - However, the app also displays sensitive values in a persistent in-page “Logs” panel. This unnecessarily exposes OTPs, setup secrets, and recovery codes in the rendered interface and conflicts with the requirement not to expose sensitive values in logs.

- **FAIL — Time-based authenticator provisioning and verification**
  - `/api/provision` generates a random secret and an unrelated random six-digit OTP.
  - `/api/otp/verify` checks only that unrelated server-generated OTP hash; it never derives an OTP from the stored shared secret and time period.
  - `decrypt()` is never used, confirming the provisioned secret is not used to validate authenticator codes.
  - This is not a TOTP authenticator flow.

- **FAIL — Functional QR-code provisioning option**
  - The displayed “QR setup square” is a CSS `repeating-conic-gradient`, not an encoded QR image.
  - It does not contain an `otpauth://` provisioning URI and cannot be scanned by an authenticator application.
  - The displayed setup key is not shown as a real standard TOTP secret/URI tied to verification.

- **FAIL — Consistent provisioning after requesting a new OTP**
  - On the OTP screen, “Get a new test code” calls `/api/provision`.
  - That endpoint creates a new secret as well as a new OTP, silently replacing the previously displayed setup key.
  - A user’s authenticator would remain configured with the old secret, while the server has replaced it with a different secret.

- **FAIL — Server-side authorization and account ownership enforcement**
  - Any requester who supplies any syntactically valid email to `/api/signin` receives an authenticated session for the fixed `ACCOUNT_ID`.
  - The server does not validate that the email belongs to Marcus/the account owner, nor does it validate a password or a pre-existing authenticated identity.
  - Likewise, the identity check accepts any four digits as the phone value and sends the verification code directly back to the requesting browser.
  - Consequently, a guessed or arbitrary email and phone format are sufficient to access and modify the fixed account’s MFA state.

- **PASS — CSRF protection on state-changing POST requests**
  - The app uses a session-bound CSRF token and verifies both `Origin` and `X-CSRF-Token` for POST API calls.
  - Cookies use `SameSite=Strict`, which provides additional CSRF protection.

- **PASS — Secure session-cookie attributes and session rotation**
  - Session cookies are set with `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - The session identifier is rotated after sign-in.
  - Idle and absolute session expiry are implemented, and logout deletes the server session and expires the cookie.

- **PARTIAL/FAIL — Verification-code security and rate limiting**
  - Identity and authenticator codes are marked single-use and expire after 15 minutes.
  - Failed valid-format codes increment a failure counter and trigger a five-minute lockout after five failures.
  - However, the lockout is only stored on the session. An attacker can obtain a new anonymous session, sign in again with any valid-format email, and continue attempting codes. This does not provide effective account-level or client-level protection against repeated attempts.
  - Invalid-format submissions also do not count toward failed-attempt limits.

- **FAIL — Strong protection of secrets and recovery codes at rest**
  - The OTP secret is AES-GCM encrypted in memory, but the encryption key is generated at process startup and is held in the same process. All MFA data is volatile and disappears on restart.
  - Backup codes are stored as unsalted plain SHA-256 hashes of only 32-bit values (`ABCD-1234`). These hashes are cheaply brute-forceable if memory/storage is exposed.
  - A keyed hash or a password-hashing/KDF approach with a per-code salt is needed for backup codes, or the values should be encrypted at rest with managed key material.

- **PASS — No browser storage of secrets or session tokens**
  - The client does not use `localStorage`, `sessionStorage`, or non-HttpOnly cookies for session tokens, OTP values, setup secrets, or backup codes.

- **PASS — Input validation and client-side output handling**
  - Email, phone suffix, OTP, and recovery-code formats are server-validated.
  - Client-generated error text is escaped before insertion into `innerHTML`; sensitive response values are inserted with `textContent`.
  - No database queries exist, so SQL injection through database query construction is not applicable in this implementation.

- **PASS — Security headers and restrictive browser policy**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, restrictive permissions policy, no-referrer policy, and no-store caching are configured.
  - Error handling returns generic errors rather than stack traces.

- **PASS — Restricted CORS behavior**
  - The server only returns CORS preflight permissions for explicitly allow-listed localhost HTTPS origins.
  - Normal API responses do not permissively expose cross-origin access.

- **FAIL — Recovery-code verification is not available in the client UI**
  - `/api/recovery/verify` exists server-side, but there is no recovery-code entry screen or navigation to it in the SPA.
  - The requirements describe recovery codes as a usable fallback if the user loses their phone; this fallback should be accessible and testable in the UI.

- **PASS — No external assets, network calls, frameworks, bundlers, or compilation pipeline**
  - The client uses vanilla browser JavaScript and same-origin `fetch`.
  - The server uses Bun directly and does not rely on external front-end assets or build tools.

## FAILING_ITEMS

- The provisioned authenticator secret is unrelated to the OTP that the server verifies; this is not a functional TOTP implementation.
- The “QR setup square” is decorative CSS, not a scannable QR code containing a provisioning URI.
- Requesting a “new test code” silently regenerates and replaces the authenticator secret, invalidating the secret that was previously shown to the user.
- `/api/signin` authenticates any valid-format email as the fixed Marcus account, so server-side account ownership is not actually enforced.
- The identity step does not validate a phone value against the account and returns the code directly to the requesting client, making it an insufficient ownership check.
- Failed-verification lockouts are session-only and can be bypassed by creating a new session and signing in again.
- Backup codes use unsalted SHA-256 hashes of low-entropy 32-bit values and are vulnerable to offline brute force.
- MFA state and encryption keys are only in process memory; restart loses all MFA data, and the encryption design does not provide meaningful durable protection at rest.
- Sensitive setup secrets, OTPs, and recovery codes are rendered in the persistent on-screen “Logs” panel. Browser `console.log` is required for the mock, but this additional visible log panel is unnecessary exposure.
- The recovery-code verification API has no corresponding client screen or functional navigation path.

## NEW_TASKS

1. Implement a real simulated TOTP mechanism in `app.ts`: generate a standards-compatible Base32 secret, create an `otpauth://totp/...` URI, and verify OTPs derived from that secret and the current allowed time window.
2. Replace the decorative CSS QR square with an actual QR representation of the generated `otpauth://` URI, while retaining a copyable/manual Base32 setup secret.
3. Change “Get a new test code” so it derives another valid test TOTP from the currently provisioned secret rather than calling provisioning and replacing the secret.
4. Implement a server-side mock authentication model that binds a verified identity to a specific account rather than assigning `ACCOUNT_ID` to every syntactically valid email submission.
5. Bind identity verification data to the authenticated account and validate the submitted phone suffix against the account’s configured mock phone suffix before issuing/verifying a code.
6. Apply failed-verification counters and lockouts at the account and/or client/IP level, not solely per session; count malformed repeated verification attempts where appropriate.
7. Replace backup-code SHA-256 storage with a strong salted password hash/KDF or keyed HMAC design, and use stronger recovery-code entropy.
8. Add durable protected storage semantics for MFA records and encryption key material, or explicitly implement an appropriate secure persistence mechanism compatible with the single-file Bun application.
9. Remove the rendered in-page sensitive “Logs” panel; retain required mock-value delivery only through browser `console.log` and the intended code/setup displays.
10. Add a recovery-code UI screen with formatted input, validation feedback, retry support, and a reachable internal navigation path to exercise `/api/recovery/verify`.

## DECISION

**FAIL**