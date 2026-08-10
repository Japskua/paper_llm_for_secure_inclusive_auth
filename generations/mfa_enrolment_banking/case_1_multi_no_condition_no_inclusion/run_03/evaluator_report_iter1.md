## SUMMARY

The artifact is a single-file Bun HTTPS SPA with a responsive mobile UI, secure-cookie settings, most security headers, CSRF checks, generic errors, and working simulated enrolment/recovery flows. However, it does not fully satisfy the MFA/security requirements: the authenticator is not actually time-based, identity verification is not rate-limited, session IDs are not rotated when identity authentication succeeds, lockout can be bypassed with a new session, and recovery-code storage/acknowledgement is not resilient to a reload. Therefore it cannot be accepted as-is.

## FUNCTIONAL_CHECK

- **FAIL — Single-file Bun application with HTML, CSS, JS, and server in `app.ts`.**  
  The supplied artifact is one `app.ts` file and uses Bun directly without imports, bundlers, frameworks, or external assets. However, overall acceptance fails due to functional/security issues below.

- **PASS — Mobile-responsive SPA UI is present and legible.**  
  The UI uses a constrained mobile layout, responsive typography, touch-sized inputs/buttons, and a narrow-screen media query.

- **PASS — Sign-in, identity verification, provisioning, OTP confirmation, recovery code generation, regeneration, recovery verification, acknowledgement, and logout routes are implemented.**  
  The client routes requests to corresponding `/api/*` endpoints, and the basic happy path works.

- **FAIL — The authenticator is not a time-based OTP/TOTP implementation.**  
  `/api/mfa/provision` creates an unrelated random six-digit `verificationCode`; `/api/mfa/confirm` compares that one stored code hash. The generated `secret` is encrypted but is never used to derive or verify the authenticator code. This is a short-lived random verification code, not a time-based one-time passcode generated from the provisioning secret.

- **FAIL — Mock values are not deterministic as required.**  
  Identity codes, authenticator codes, secrets, and recovery codes are all randomly generated. The requirement explicitly calls for simulated delivery/provisioning/verification using deterministic mock values, while retaining secure generation where security-sensitive production behavior is represented. The current implementation provides test values, but not deterministic test fixtures.

- **PASS — Manual authenticator setup is available.**  
  The provisioning screen displays the generated secret as a “Manual secret,” returns it to the UI, and writes it to the browser console.

- **PASS — Test OTP and backup-code values are returned to the UI and logged in the browser console.**  
  `logTest()` calls `console.log()` in browser-side JavaScript, and the identity code, authenticator secret/code, and recovery codes are shown to the user for simulation/testing.

- **PASS — Server-side user ownership is not derived from browser-supplied user IDs.**  
  The server ignores client user identity fields and assigns `userId: "account-owner-marcus"` internally. MFA lookups are performed using the authenticated session’s server-side `userId`, preventing a direct user-ID manipulation/IDOR payload.

- **FAIL — Authentication/authorization is not sufficiently robust for the account owner.**  
  Any client that submits syntactically valid email and phone values receives a session for the fixed `"account-owner-marcus"` account and receives the identity code in the response/UI. In a simulation this may be acceptable only if clearly constrained as a mock account, but it does not genuinely establish that the requester is the account owner before allowing MFA settings to be modified.

- **PASS — CSRF protection is applied to state-changing endpoints.**  
  State-changing endpoints require a session-bound CSRF token; the cookie is `SameSite=Strict`; cross-origin `Origin` values are rejected by `validCsrf()`.

- **PASS — Core response hardening headers are set.**  
  The server supplies CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, and `Permissions-Policy`.

- **PASS — Session cookie flags meet the stated cookie requirements.**  
  The session cookie uses `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, and a bounded `Max-Age`.

- **PASS — HTTPS/TLS is configured using the required certificate paths.**  
  `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`.

- **PASS — CORS is restricted to trusted localhost TLS origins.**  
  `Access-Control-Allow-Origin` is only returned for allow-listed `https://localhost`, `https://127.0.0.1`, or `https://[::1]` origins.

- **PASS — Sensitive material is not put in URL query strings, browser storage, or server logs.**  
  No `localStorage`/`sessionStorage` is used, secrets are not placed in URLs, and the server does not log OTPs, secrets, recovery codes, or session IDs. Browser console output is deliberately used for test-only values as required.

- **PARTIAL/FAIL — At-rest protection of backup codes is incomplete.**  
  OTP secrets are encrypted using AES-GCM, and recovery codes are hashed. However, recovery codes are hashed with bare unsalted SHA-256. Recovery codes are authentication credentials and should use a per-code salt plus a password-hashing/KDF approach, or a keyed server-side hash, rather than fast unsalted hashes.

- **PASS — Inputs are allow-listed and server-validated.**  
  JSON bodies reject unexpected keys, email/phone/OTP/recovery-code formats are checked, and no database or SQL query surface exists.

- **PASS — Client rendering avoids dynamic HTML interpolation for sensitive values.**  
  Secrets and recovery codes are inserted via `textContent`; user-entered fields are not reflected into HTML.

- **PASS — Redirect input is allow-listed.**  
  `redirect` is limited to `undefined`, `/`, or `/#signin`; although it is not subsequently used, it is not an open redirect.

- **FAIL — Identity verification lacks failed-attempt rate limiting and lockout.**  
  `/api/identity` rejects invalid codes but never increments `failedAttempts`, never sets `lockedUntil`, and does not otherwise rate-limit attempts. This violates the requirement to rate-limit and lock out repeated failed verification attempts.

- **FAIL — MFA/recovery lockout can be bypassed by creating a new session.**  
  Failed-attempt and lockout fields are held only on `Session`. A caller can start another sign-in session and receive a new unblocked `failedAttempts`/`lockedUntil` state for the same fixed account. Lockout/rate-limit state needs to be account- and challenge-scoped server-side, not solely session-scoped.

- **PASS — Provisioning OTPs and recovery codes are single-use and time-bound where applicable.**  
  Provisioning codes have a five-minute expiry and `verificationUsed`; recovery code hashes are removed after use.

- **FAIL — Session IDs are not rotated when authentication state is elevated.**  
  A session ID is created at `/api/signin`, but `/api/identity` changes `identityVerified` from false to true without issuing a new session ID/cookie. Identity verification is the meaningful authentication step, so the session identifier must be regenerated there to satisfy session-fixation protection.

- **PASS — Idle and absolute session expiration are implemented.**  
  `getSession()` enforces 20-minute idle and 8-hour absolute expiry.

- **PASS — Logout invalidates the current session and expires the cookie.**  
  `/api/logout` deletes the server-side session and sends an expired cookie.

- **PASS — Errors are generic and do not expose server stack traces.**  
  `genericFailure()` returns a generic response; the top-level catch returns a generic 500 error.

- **FAIL — Recovery-code saving/acknowledgement is not reload-safe.**  
  Generated plaintext recovery codes exist only in client memory (`shownCodes`). If the user reloads before acknowledgement, `/api/status` renders the dashboard without codes, while the server retains only hashes. The user is told to save/acknowledge codes but can no longer view/download them unless they regenerate them. The application should preserve a pending recovery-code presentation securely for the active enrolment flow, or require regeneration before acknowledgement when the plaintext set is no longer available.

## FAILING_ITEMS

- The provisioned secret is not used to compute or validate a time-based OTP; the application uses an independent random one-time verification code instead of TOTP.
- Mock delivery/provisioning values are random rather than deterministic test values.
- The sign-in simulation maps any format-valid email/phone submission to Marcus’s account, so account-owner authentication is not meaningfully enforced.
- Identity-code verification has no failed-attempt tracking, throttling, or temporary lockout.
- MFA OTP and recovery-code lockouts are stored only in a session and can be reset by obtaining another session.
- The session identifier is not regenerated after successful identity verification.
- Recovery code hashes use fast unsalted SHA-256 rather than a salted/KDF or keyed credential-verification design.
- A page reload before recovery acknowledgement loses the only plaintext recovery-code display/download state, yet acknowledgement remains possible.

## NEW_TASKS

1. Replace the independent provisioning verification code with a simulated TOTP flow derived from the generated provisioning secret, using a defined time step and a testable deterministic clock/code fixture; keep the manual secret-entry UX.
2. Define and implement deterministic browser-visible test fixtures for simulated identity and authenticator delivery while preserving cryptographically secure generation for production-sensitive secrets and recovery codes, or provide an explicit test-only mode that cannot be enabled in production.
3. Make the mock authentication model explicit and account-bound: only allow the configured simulated Marcus identity to establish the Marcus session, and keep user/account identity exclusively server-side.
4. Add failed-attempt counters, rate limiting, and temporary lockout to identity-code verification.
5. Move MFA verification/recovery failure counters and lockout state from `Session` to server-side account/challenge state so a new session cannot bypass lockout.
6. On successful identity verification, create a replacement authenticated session, invalidate the old session, issue the replacement `mfa_session` cookie, and return the replacement CSRF token.
7. Store recovery-code verifiers using a per-code salt and a suitable password-hashing/KDF or keyed server-side verifier; continue removing the matching verifier after successful use.
8. Make pending recovery-code acknowledgement reload-safe: either securely retain pending plaintext codes only for the active authenticated enrolment session or, after reload, require recovery-code regeneration before allowing acknowledgement and clearly explain this to the user.

## DECISION

FAIL