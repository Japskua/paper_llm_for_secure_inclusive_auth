## SUMMARY

The artifact is a valid single-file Bun HTTPS SPA with strong baseline controls: TLS configuration, secure cookies, CSP/HSTS/clickjacking headers, CSRF checks, input validation, session rotation, rate limiting, encrypted draft MFA secrets, and hashed recovery codes. The mobile UI and core enrolment flow are largely implemented. However, it does not fully meet the requirements because MFA data is stored only in a session and is lost on logout/re-authentication, recovery codes are not logged in the browser as required, and the requested deterministic browser-side mock/disclosure behavior is incomplete.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun server and SPA, with no build tooling or external assets.**  
  `app.ts` contains the Bun server, generated HTML, inline CSS, and vanilla client-side JavaScript. No framework, bundler, compiler, database library, or external network asset is used.

- **PASS — HTTPS/TLS server configuration is present.**  
  `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`, matching the required certificate locations.

- **PASS — Mobile-responsive and legible UI is implemented.**  
  The HTML includes a mobile viewport meta tag, constrained mobile-friendly layout, large inputs/buttons, focus styles, semantic headings/forms/labels, and readable contrast.

- **PASS — MFA enrolment flow functions within a live session.**  
  The flow supports sign-in, identity-code verification, manual authenticator secret setup, TOTP verification, recovery-code generation, recovery-code consumption, regeneration, and logout.

- **PASS — Manual authenticator setup is available.**  
  The provisioning endpoint returns `manualSecret`, and the UI renders a setup key that can be entered manually into an authenticator app. No QR code is required because a manual path is provided.

- **FAIL — MFA enrolment state is not persisted at the account level.**  
  `encryptedMfaSecret` and `recoveryCodes` are stored only on `Session`. Both are lost when the user logs out, their session expires, the server restarts, or a new authentication session is created. A subsequent sign-in creates a fresh authenticated session with no MFA configuration, and `/api/bootstrap` reports `mfaEnrolled: false`. This does not meet the expected “MFA settings”/“at rest” behavior for a bank account.

- **PASS — Server-side authorization and IDOR prevention are substantially implemented.**  
  MFA routes require an authenticated session with the hard-coded account owner identity (`marcus-account-001`), and request bodies containing user/account/owner identifier fields are rejected. Client-supplied identifiers cannot select another account.

- **PASS — CSRF protection is applied to state-changing JSON endpoints.**  
  State-changing requests require a session-bound CSRF token, and cookies use `SameSite=Strict`. Origin checks are also applied to API requests.

- **PASS — Secure response headers and restrictive CORS are implemented.**  
  The application sets CSP with a nonce, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, and a restrictive permissions policy. CORS headers are emitted only for configured localhost TLS origins.

- **PASS — Session cookie attributes and session lifecycle protections are implemented.**  
  The session cookie is `HttpOnly`, `Secure`, `SameSite=Strict`, and uses the `__Host-` prefix with `Path=/`. Sessions have idle and absolute timeouts, rotate after sign-in and identity verification, and are invalidated on logout.

- **PASS — Input validation and output encoding are present.**  
  Email, phone, OTP, setup-secret, and recovery-code input are validated server-side. Dynamic UI values are escaped before insertion into HTML.

- **PASS — Recovery codes use CSPRNG generation and are stored as salted hashes.**  
  Recovery codes and salts are generated with `crypto.getRandomValues`; only salted SHA-256 digests are stored. Recovery codes are marked used after successful verification.

- **PASS — MFA draft secret is encrypted while stored server-side.**  
  The provisioning secret is encrypted using AES-GCM before being stored in the session draft.

- **PASS — Verification expiry, failure limits, and lockouts are implemented.**  
  Identity codes expire, provisioning drafts expire, and identity/MFA/recovery verification attempts are rate-limited with lockout windows.

- **FAIL — Recovery codes are not shown in browser `console.log` as explicitly required.**  
  Recovery codes are returned to the UI, but the client only logs generic messages such as `"Authenticator confirmed. Recovery codes are ready to copy or write down."` and `"Replacement recovery codes generated..."`. It never logs the actual generated recovery-code values.

- **FAIL — The required deterministic mock/disclosure behavior is incomplete.**  
  Identity verification codes are generated randomly by `randomDigits()`, and TOTP values vary with time. They are only disclosed to the browser when a user enables the client-controlled test-mode checkbox. This does not provide deterministic mock values for test execution, and the ordinary simulated delivery path logs only a generic message rather than the value needed to perform the simulated verification.

- **FAIL — Recovery-code verification is exposed before MFA enrolment is complete.**  
  `/api/recovery/verify` checks only `authenticated(session)`, not whether `session.encryptedMfaSecret` exists. An authenticated but unenrolled session can call the route. It cannot successfully consume a code in the current implementation because no codes exist, but the endpoint should explicitly require enrolled MFA state.

- **PASS — Generic error handling avoids stack-trace disclosure.**  
  Errors return a generic message and the top-level handler does not expose exception details.

## FAILING_ITEMS

- MFA secrets and recovery-code records are attached to the transient `Session` object rather than an account-owned MFA record. Logging out or re-authenticating destroys the account’s MFA configuration.
- `/api/bootstrap` consequently cannot report durable MFA enrolment status after a new session is created.
- Actual recovery-code values are never emitted through browser `console.log`, contrary to the explicit testing deliverable.
- Identity codes and TOTP test codes are not deterministic mock values; they are random/time-dependent and only conditionally disclosed in test mode.
- `/api/recovery/verify` does not explicitly reject authenticated users who have not completed MFA enrolment.

## NEW_TASKS

1. Create an in-memory account/MFA record keyed by the authenticated account ID, and move `encryptedMfaSecret`, recovery-code hashes, recovery attempt state, and enrolment status from `Session` into that account-owned record.
2. Update MFA provisioning confirmation, recovery verification, recovery regeneration, and `/api/bootstrap` to read and modify the account-owned MFA record so enrolment survives logout, session rotation, and subsequent sign-in.
3. Require a completed account MFA enrolment record in `/api/recovery/verify` before processing or rate-limiting a submitted recovery code.
4. Update the browser client so that generated recovery-code values are logged with `console.log` when they are received from `/api/mfa/confirm` and `/api/recovery/regenerate`.
5. Implement a clearly isolated test/mock mode that supplies deterministic test verification values and logs those values in the browser, while retaining CSPRNG-generated production verification values and ensuring test disclosure is not enabled in production operation.

## DECISION

**FAIL**