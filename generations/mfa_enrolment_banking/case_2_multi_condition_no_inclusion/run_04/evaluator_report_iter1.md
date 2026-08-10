## SUMMARY

The artifact is a single-file Bun HTTPS SPA with a generally solid mobile MFA flow, CSP/security headers, CSRF checks, secure session-cookie attributes, input validation, rate limits, and functional simulated identity/backup-code verification. However, it does not implement a time-based authenticator OTP, retains the MFA seed and provisioning OTP in plaintext server session state, and does not give the identity-verification code its own short expiration. These security and functional gaps prevent acceptance.

## FUNCTIONAL_CHECK

- **Single `app.ts` artifact with Bun server, inline HTML/CSS/JS, no frameworks/build tooling — PASS**
  - The server, HTML template, CSS, and browser JavaScript are all in `app.ts`.
  - No external assets, external requests, bundlers, or compilation steps are used.

- **HTTPS/TLS is configured using the specified certificate paths — PASS**
  - `Bun.serve` uses `certs/cert.pem` and `certs/key.pem`.
  - HSTS is sent in response headers.

- **Mobile-responsive, legible SPA with semantic and accessible UI — PASS**
  - The viewport is configured, content is constrained to a mobile-friendly width, controls have large touch targets, and text sizing is reasonable.
  - Forms use labels, error containers use `role="alert"`, and status updates use `aria-live`.

- **End-to-end enrolment flow works in the browser — PASS**
  - The flow supports mock sign-in, identity-code verification, authenticator setup-key display/manual entry, authenticator confirmation, recovery-code display, recovery verification, regeneration, and logout.
  - Browser-side mocks are logged with `console.log`, as required.

- **Manual authenticator-secret entry is available — PASS**
  - The setup key is shown and can be entered manually in the `manualSecret` field.
  - No QR code or provisioning URI is offered, so no corresponding alternate submission route is required.

- **All internal navigation/actions function without external links — PASS**
  - The confirmation, recovery, done, back, and logout actions are functional SPA transitions.
  - No open redirect is present; supplied redirect values are restricted to an internal allow-list.

- **Server-side authorization and IDOR protections — PASS**
  - MFA provisioning, confirmation, recovery verification, and recovery regeneration require an authenticated owner-bound session via `authenticated(session)`.
  - Client-submitted account/user identifier fields are rejected by `hasManipulatedIdentity`.
  - The server does not use client-controlled user IDs to select MFA state.

- **CSRF protection for state-changing endpoints — PASS**
  - State-changing requests require a session-bound CSRF token.
  - The session cookie also uses `SameSite=Strict`.
  - CSRF tokens are rotated when sessions are rotated during sign-in and identity verification.

- **Secure response headers and CORS restrictions — PASS**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, and restrictive permissions policy headers are set.
  - CORS responses are restricted to the localhost TLS origin allow-list.
  - Generic errors prevent stack traces from being returned.

- **Session-cookie configuration and session lifecycle — PASS**
  - The cookie uses `HttpOnly`, `Secure`, `SameSite=Strict`, and the `__Host-` prefix with `Path=/`.
  - Sessions have idle and absolute timeouts.
  - Session identifiers are rotated at authentication transitions.
  - Logout deletes server-side session state and expires the cookie.

- **Recovery-code generation, storage, and one-time use — PASS**
  - Recovery codes are generated using `crypto.getRandomValues`.
  - Only salted SHA-256 digests are retained server-side after issuance.
  - A matched recovery code is marked used and cannot be reused.
  - Regeneration replaces the previous recovery-code set.

- **Authenticator implementation is a true time-based OTP authenticator — FAIL**
  - `/api/mfa/provision` generates a random `draft.otp`, and `/api/mfa/confirm` compares the submitted code directly against that static value.
  - The code is not derived from the displayed setup secret and current time, so an actual authenticator app cannot generate it from the supplied key.
  - This is a temporary random verification code, not a TOTP implementation.

- **OTP/verification codes are explicitly time-bound and single-use — FAIL**
  - The MFA provisioning code has a five-minute expiry and becomes used after successful confirmation.
  - However, `identityCode` has no dedicated issue timestamp or expiration. It can remain valid as long as the identity session remains active, potentially up to the eight-hour absolute session lifetime.
  - This does not meet the requirement for verification codes to be time-bound independently of session duration.

- **MFA seed is protected at rest throughout server-side handling — FAIL**
  - Although `encryptedSecret` is created with AES-GCM, the same MFA seed is also retained as plaintext in `session.draft.manualSecret`.
  - The provisioning OTP is likewise stored in plaintext as `session.draft.otp`.
  - The plaintext seed should not be retained in server session state when an encrypted value plus secure verification mechanism can be used instead.

- **Input validation, XSS prevention, and injection protections — PASS**
  - Inputs are type/length/format validated for email, phone, OTP, recovery code, and manual secret.
  - There is no database layer or dynamic SQL.
  - Dynamic content containing secrets is inserted through `textContent`; user-controlled form input is not reflected through `innerHTML`.
  - The CSP further reduces script-injection impact.

- **No secrets in URLs, non-HttpOnly browser storage, server logs, or error output — PASS**
  - No `localStorage`, `sessionStorage`, URL query-secret handling, or server secret logging is present.
  - The browser console/UI exposure of test values is intentional and explicitly required for this mock/testing artifact.

## FAILING_ITEMS

- The authenticator confirmation mechanism is not TOTP. It verifies a server-generated random six-digit value rather than a time-step-based OTP derived from the displayed base32 secret.
- The identity verification code has no independent expiration field/check. Session activity can keep an identity code usable much longer than a normal verification-code validity period.
- The MFA shared secret is retained in plaintext in `Draft.manualSecret`, despite also being encrypted in `Draft.encryptedSecret`.
- The provisioning OTP is retained as plaintext in `Draft.otp`; verification should use a derived TOTP value or a protected digest rather than preserving the raw OTP.

## NEW_TASKS

1. Replace the static `Draft.otp` confirmation design with a standards-compatible TOTP calculation derived from the generated base32 secret and a short time step (for example, 30 seconds), with a narrowly defined allowed clock-skew window.
2. Update `/api/mfa/confirm` to validate the submitted OTP against the TOTP derived from the provisioned secret, rather than comparing it with a stored random OTP.
3. Remove plaintext `manualSecret` and `otp` fields from `Draft`; retain only the AES-GCM encrypted seed and the minimal provisioning metadata required for expiry, failure counts, and lockout.
4. Add AES-GCM decryption support server-side, restricted to the MFA-confirmation path, so the encrypted draft seed can be used to calculate/validate TOTP without retaining plaintext in session state.
5. Add an explicit `identityCodeExpiresAt` field when issuing the identity code and reject/delete the code after a short verification window regardless of session idle or absolute lifetime.

## DECISION

FAIL