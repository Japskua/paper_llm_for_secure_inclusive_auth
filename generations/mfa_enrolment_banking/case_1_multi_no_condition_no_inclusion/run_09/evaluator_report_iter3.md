## SUMMARY

The artifact is a strong single-file Bun MFA enrolment implementation with server-side session ownership checks, CSRF validation, TLS, secure cookie attributes, encrypted TOTP-secret storage, hashed recovery codes, input validation, rate limiting, and a responsive mobile UI. However, it does not fully meet the security and flow requirements because its CSP explicitly permits arbitrary inline script/style execution, and an unauthenticated user can directly navigate to the confirmation route and see a false “MFA is active” confirmation screen.

## FUNCTIONAL_CHECK

- **PASS — Server-side authorization and IDOR prevention**
  - MFA API endpoints derive the account exclusively from the authenticated server-side session (`s.accountId`).
  - No client-provided account or user identifier is accepted by MFA endpoints.
  - Session ownership is checked for state, provisioning, OTP verification, backup-code regeneration, recovery-code verification, and logout.

- **PASS — CSRF protection for authenticated state-changing actions**
  - Authenticated POST endpoints require both a session-bound CSRF token (`X-CSRF-Token`) and an allow-listed `Origin`.
  - Session cookies use `SameSite=Strict`, further reducing cross-site request exposure.
  - Pre-authentication challenge/sign-in requests also require a trusted Origin.

- **FAIL — Secure CSP configuration**
  - A CSP header is present, along with HSTS, `X-Content-Type-Options`, `X-Frame-Options`, `frame-ancestors 'none'`, and restrictive CORS.
  - However, the CSP contains both `script-src ... 'unsafe-inline'` and `style-src ... 'unsafe-inline'`.
  - `unsafe-inline` permits arbitrary inline scripts and styles, materially weakening CSP/XSS protection and does not satisfy the intent of a secure CSP for an authentication/enrolment application.

- **PASS — Secure HTTP headers, CORS, and generic errors**
  - HSTS, CSP, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`, and `Cache-Control: no-store` are set.
  - CORS only permits explicitly trusted localhost TLS origins.
  - Exceptions are caught and returned as generic JSON errors without stack traces.

- **PASS — Secure session management**
  - Session cookies are `HttpOnly`, `Secure`, `SameSite=Strict`, scoped to `Path=/`, and use the valid `__Host-` prefix pattern.
  - Sessions have idle and absolute expiration.
  - Sign-in deletes a previous session before issuing a fresh random session ID, mitigating session fixation.
  - Logout invalidates the server-side session and expires the cookie.
  - Browser storage APIs are not used for secrets or session tokens.

- **PASS — Cryptographic protection of MFA material**
  - TOTP secrets are generated with `crypto.getRandomValues` and encrypted at rest using AES-GCM.
  - Recovery codes are generated using cryptographically secure randomness and stored using PBKDF2-SHA-256 with unique salts.
  - Raw recovery codes are only returned for the simulated display/logging flow and are not retained in the record.
  - HTTPS/TLS is configured with the provided certificate paths, and non-HTTPS requests are rejected.

- **PASS — Input validation, output handling, and redirect safety**
  - Email, international phone, identity code, OTP, and recovery-code formats are validated server-side.
  - There is no SQL/database layer, so parameterized-query concerns do not apply to this implementation.
  - User-controlled values are not interpolated into server HTML; dynamic UI rendering uses `textContent` where sensitive/dynamic display is needed.
  - Redirect values are restricted to an allow-list, and no client-controlled external redirect is performed.

- **PASS — OTP and recovery-code protections**
  - TOTP verification is limited to a short time window and prevents reuse of an accepted counter.
  - Identity challenges are short-lived and single-use.
  - Recovery codes are marked used after successful validation and cannot be reused.
  - OTP, identity-challenge, and recovery-code failures are rate-limited and lock after repeated failures.

- **FAIL — Authentication-aware confirmation flow**
  - `/confirmed` is rendered by the client without checking that a session exists or that MFA is enabled.
  - A fresh unauthenticated browser can load `#/confirmed` and see “MFA is active” / “Enrolment confirmed,” despite never completing enrolment.
  - This is a misleading and manipulable internal flow state. The confirmation screen must require authenticated state with `mfa.enabled === true`, similarly to settings and other protected workflow views.

- **PASS — Mobile SPA UX, manual provisioning, and internal links**
  - The UI is responsive and constrained to a mobile-friendly content width.
  - TOTP setup supports manual secret entry, satisfying the requirement when no QR code is offered.
  - Simulated identity codes, TOTP codes, and recovery codes are exposed through browser-side `console.log` and the UI log area for testing.
  - Internal hash links for setup, verification, backup-code display, settings, and logout function.

- **PASS — Single-file and zero-build compliance**
  - The server, HTML, CSS, and browser-side vanilla JavaScript are contained in one `app.ts` file.
  - No framework, bundler, compiler step, external asset, external network call, or external JavaScript dependency is used.
  - TLS certificate files are the only expected runtime files and are explicitly required by the specification.

## FAILING_ITEMS

- The CSP uses `'unsafe-inline'` for scripts and styles:
  - `script-src 'self' 'unsafe-inline'`
  - `style-src 'self' 'unsafe-inline'`
  - This weakens the intended XSS protection of CSP and is not appropriate for an MFA enrolment flow.

- The client-side `confirmed()` route lacks an authentication/MFA-state guard:
  - Navigating directly to `https://localhost:3000/#/confirmed` in a new unauthenticated session renders a successful MFA confirmation.
  - The UI must not claim MFA completion unless the authenticated server-backed state confirms MFA is enabled.

## NEW_TASKS

1. Replace the CSP’s `unsafe-inline` allowances with nonce- or hash-based CSP protection for the inline `<script>` and `<style>` blocks. Generate a cryptographically random nonce per HTML response, include it in the CSP header, and apply it to the corresponding inline elements.

2. Protect the `confirmed()` client route by requiring both an authenticated state object and `st.mfa.enabled === true`; otherwise route the user to sign-in or the appropriate setup/settings screen instead of rendering the MFA-success message.

## DECISION

FAIL