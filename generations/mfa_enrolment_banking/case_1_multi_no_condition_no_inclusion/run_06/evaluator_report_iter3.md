## SUMMARY

The artifact is a valid single-file Bun/TypeScript MFA enrolment SPA with TLS configuration, responsive mobile-oriented UI, session-based authorization, CSRF checks, encrypted TOTP secret storage, hashed recovery codes, and working simulated enrolment/verification flows. However, it does not fully meet the security requirements because its CORS implementation permits arbitrary same-origin values rather than only the explicit trusted-origin allow-list, and it renders sensitive mock secrets in an on-page “Logs” panel. These issues require correction before acceptance.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no framework, bundler, compiler, or external assets.**  
  `app.ts` contains the Bun server, inline HTML, inline CSS, and vanilla browser JavaScript. It uses no external network resources or frontend build tooling.

- **PASS — TLS is configured using the required certificate paths.**  
  Bun is configured with:
  ```ts
  cert: Bun.file("certs/cert.pem"),
  key: Bun.file("certs/key.pem"),
  ```
  and serves HTTPS directly.

- **PASS — Mobile-responsive, semantic SPA UI is present.**  
  The page uses semantic elements such as `header`, `main`, `section`, `aside`, `form`, and `label`. CSS constrains the main layout to a mobile-friendly width and includes a narrow-screen media query.

- **PASS — Sign-in and identity verification flow works with deterministic configured identity data.**  
  The sign-in endpoint validates the configured Marcus email and phone combination, uses generic failures, and the client provides a functional sign-in form.

- **PASS — MFA provisioning and manual authenticator secret entry work.**  
  `/api/mfa/provision` generates a secure Base32 secret, encrypts it at rest, returns it to the client, and the UI displays it for manual authenticator setup.

- **PASS — TOTP verification is time-bound and enrolment verification is single-use.**  
  TOTP uses a 30-second moving time step. A successful verification sets `verification.used = true`, preventing reuse of the same enrolment verification state.

- **PASS — MFA activation and recovery-code generation work.**  
  After successful TOTP verification, the enable endpoint generates ten recovery codes, stores only their peppered SHA-256 hashes, and returns the plaintext codes once for the client to display.

- **PASS — Recovery-code verification and consumption work.**  
  Recovery codes are validated, hashed, matched using timing-safe comparison, removed after successful use, and remaining-code count is returned.

- **PASS — Server-side authorization prevents direct user-ID manipulation / IDOR.**  
  MFA endpoints derive identity exclusively from the opaque `mfa_session` cookie. `authorize()` rejects request query parameters such as `id`, `uid`, `userId`, and `accountId`, and request bodies containing those fields are rejected.

- **PASS — CSRF protection exists on authenticated state-changing actions.**  
  Logout, provisioning, trusted reset, TOTP verification, MFA enablement, recovery-code regeneration, and recovery-code verification require the per-session `X-CSRF-Token`.

- **PASS — Session security controls are largely implemented.**  
  Session cookies include `HttpOnly`, `Secure`, and `SameSite=Strict`. Sessions are rotated at sign-in, use idle and absolute expiry checks, and are invalidated by logout.

- **PASS — Security headers are set.**  
  Responses include CSP with nonces, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, referrer policy, permissions policy, and `Cache-Control: no-store`.

- **PASS — Secrets are protected at rest and generated with cryptographically secure randomness.**  
  The TOTP secret is protected using AES-GCM, recovery codes are generated using `crypto.getRandomValues`, and recovery codes are stored as peppered hashes.

- **PASS — Server-side validation and output-safety measures are present.**  
  Email, phone, OTP, and recovery-code input have server-side validation. Client-rendered variable content uses `textContent` rather than interpolating user-provided values into HTML.

- **PASS — Generic errors and sign-in anti-enumeration protections are implemented.**  
  Invalid sign-in inputs and wrong credentials receive the same generic 401 response, with a minimum response duration and keyed lockout tracking.

- **FAIL — CORS is not restricted exclusively to trusted origins.**  
  `applyCors()` accepts an origin whenever it equals `new URL(request.url).origin`, even if that origin is not in `TRUSTED_ORIGINS`:
  ```ts
  if (origin !== requestOrigin && !TRUSTED_ORIGINS.has(origin)) return false;
  ```
  This means an arbitrary host/origin can be accepted if it matches the request URL origin, rather than CORS being limited solely to the declared localhost origins. Same-origin requests do not require CORS headers, so this exception is unnecessary and violates the explicit trusted-origin-only requirement.

- **FAIL — Sensitive secrets are rendered in the application’s on-page “Logs” area.**  
  The browser `audit()` function both calls `console.log()` and appends the same sensitive values to the visible `#logs` panel:
  ```ts
  audit("Simulated authenticator provisioning — manual secret: "+d.secret);
  audit("Simulated current TOTP-style verification OTP: "+d.testOtp+" ...");
  audit("Simulated recovery codes generated: "+d.codes.join(", "));
  ```
  The requirements explicitly prohibit exposing OTP seeds, OTPs, and backup codes in logs. The testing deliverable requires browser `console.log` mock output, but it does not require displaying those sensitive values in an on-page log panel. The sensitive values should remain in their intended provisioning/recovery UI and, if required for testing, in browser console output only.

## FAILING_ITEMS

- **CORS allow-list bypass:** `applyCors()` trusts any `Origin` equal to the request URL’s origin, rather than accepting only entries in `TRUSTED_ORIGINS`.
- **Sensitive values shown in visible application logs:** the `#logs` panel displays TOTP secrets, current OTPs, and recovery codes, contrary to the requirement not to expose them in logs.

## NEW_TASKS

1. Update `applyCors()` so that any request with an `Origin` header is accepted only when `origin` is a member of `TRUSTED_ORIGINS`; remove the `origin === requestOrigin` bypass. Do not emit CORS headers for absent origins or untrusted origins.

2. Split browser console test logging from visible UI logging. Keep the required browser `console.log()` calls for simulated OTP and recovery-code testing, but ensure the visible `#logs` panel receives only redacted/status-only messages, such as “Authenticator provisioning simulated” and “Recovery codes generated.”

3. Verify that no other visible log/error path includes the provisioning secret, current OTP, recovery codes, session token, or encrypted-secret values.

## DECISION

**FAIL**