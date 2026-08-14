## SUMMARY

The artifact is a single-file Bun/TypeScript MFA enrolment SPA with functional sign-in, identity confirmation, TOTP-style authenticator provisioning and verification, backup-code generation/regeneration, recovery-code verification, mobile-responsive UI, TLS, secure headers, session handling, validation, and browser-side mock logging. Most requirements are met. However, the login endpoint creates/rotates sessions without CSRF protection, which violates the requirement to protect **all state-changing requests**.

## FUNCTIONAL_CHECK

- **PASS — Single-file, zero-compilation implementation**
  - The complete Bun server, HTML, CSS, and browser JavaScript are contained in `app.ts`.
  - It uses `Bun.serve()` directly and does not depend on frameworks, bundlers, package imports, external assets, or external network calls.

- **PASS — TLS/HTTPS configuration**
  - Bun is configured with `certs/cert.pem` and `certs/key.pem`.
  - The server only serves through the TLS configuration and sends HSTS headers.

- **PASS — Mobile-responsive and legible SPA UI**
  - The page includes the mobile viewport meta tag.
  - CSS provides responsive behavior at narrow widths, including full-width controls below 430px.
  - The enrolment steps are presented as a mobile-friendly flow.

- **PASS — Sign-in, identity, authenticator, recovery-code, and logout flows function**
  - The client routes internally between sign-in, identity, provisioning, verification, confirmation, dashboard, and recovery pages.
  - Internal hash links are handled by `route()` and `hashchange`.
  - MFA can be provisioned, verified, enabled, recovery codes displayed, regenerated, and used once.
  - Logout invalidates the server-side session and clears the cookie.

- **PASS — Provisioning secret and OTP can be submitted manually**
  - `/api/provision` returns a manual Base32 setup secret and a test OTP.
  - The UI displays the setup secret and requires manual secret and OTP entry on the verification screen.
  - This satisfies the manual-entry requirement without relying on a QR code.

- **PASS — Browser-side mock logging**
  - Provisioning secrets, current test OTPs, and recovery codes are emitted through browser `console.log()` via `mockLog()`.
  - They are also visible in the test-only in-page log area, enabling the simulated verification flow.

- **PASS — Server-side authorization and IDOR resistance**
  - MFA endpoints derive the user exclusively from the authenticated server-side session.
  - Client-provided identifiers such as `userId`, `accountId`, and `ownerId` are explicitly rejected.
  - MFA state is accessed through `auth.session.userId`, not a client-selected identifier.

- **FAIL — CSRF protection on all state-changing requests**
  - Authenticated MFA-changing endpoints validate `X-CSRF-Token`.
  - However, `POST /api/login` creates a new authenticated session, rotates/removes an existing session, and sets a session cookie without validating a CSRF token or enforcing a robust request-origin/fetch-metadata check.
  - This permits login-CSRF/session-setting risks and does not meet the stated requirement that CSRF protection apply to **all state-changing requests**.

- **PASS — Secure headers and CORS restrictions**
  - Responses include CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, and `Cache-Control: no-store`.
  - CORS only permits the configured localhost TLS origins and supports credentials only for those origins.
  - Untrusted explicit `Origin` headers are rejected.

- **PASS — Secure session-cookie configuration and session lifecycle**
  - Session cookies use `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, and a bounded `Max-Age`.
  - Sessions are rotated on successful login.
  - Idle and absolute expiry are enforced server-side.
  - Logout deletes the server-side session and expires the cookie.

- **PASS — Secret and recovery-code protection at rest**
  - TOTP secrets are AES-GCM encrypted before storage in the user record.
  - Recovery codes are generated from `crypto.getRandomValues()` and only SHA-256 digests with a process-local pepper are retained.
  - The code does not persist secrets, OTPs, backup codes, or session tokens in `localStorage`, `sessionStorage`, or client-readable session cookies.

- **PASS — Input validation and output-safe rendering**
  - Email, phone, OTP, secret, and recovery-code inputs are validated server-side.
  - Request bodies containing account-owner identifier fields are rejected.
  - Dynamic client output uses `textContent` or DOM node creation rather than interpolating user-controlled values into HTML.
  - Redirect/hash destinations are constrained by `safeInternalPath()`.

- **PASS — OTP/recovery-code expiry, single use, and lockout controls**
  - TOTP verification uses the current 30-second step and records consumed steps in `usedSteps`.
  - Provisioning expires after 15 minutes.
  - Recovery codes are removed after successful use.
  - Authentication and recovery verification failures are tracked and locked after repeated failures.
  - Recovery-code regeneration is rate-limited.

- **PASS — Generic error handling and reduced enumeration exposure**
  - Server exceptions are caught and produce generic responses without stack traces.
  - Login failures use a shared generic response for malformed, unknown, invalid-password, and locked submissions.
  - Credential processing uses fixed-width digesting and timing-safe comparisons.

## FAILING_ITEMS

- `POST /api/login` is a state-changing endpoint because it creates a new authenticated session, deletes any prior session identified by the request cookie, and issues a `Set-Cookie` session credential. It does not require a CSRF token.
- The existing `SameSite=Strict` session cookie does not by itself provide complete login-CSRF protection because an attacker can potentially trigger a cross-site login submission that establishes an attacker-controlled authenticated session in the victim’s browser. A server-validated pre-authentication anti-CSRF mechanism or a robust origin/fetch-metadata policy is required.

## NEW_TASKS

1. Add pre-authentication CSRF protection for `POST /api/login`: issue a server-generated login CSRF token during initial page delivery or through a dedicated same-origin bootstrap endpoint, submit it from the sign-in form, and validate it server-side before processing credentials or setting a session cookie.
2. Ensure the login CSRF token is bound to a secure, short-lived server-side/pre-auth session context and is rotated or invalidated after successful login.
3. Add an explicit server-side same-origin/fetch-metadata validation for login requests as defense in depth, rejecting cross-site login submissions even if a token validation path is bypassed.

## DECISION

**FAIL**