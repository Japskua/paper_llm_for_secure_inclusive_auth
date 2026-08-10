## SUMMARY

The artifact is a well-structured single-file Bun HTTPS SPA with strong coverage of the MFA enrolment, session, CSRF, input-validation, CSP, TLS, and mobile UX requirements. However, the MFA confirmation operation is not atomic: concurrent confirmation requests can successfully reuse the same draft TOTP setup. This violates the requirement that verification codes be single-use and can issue recovery-code responses that are no longer the active server-side set. Therefore, the artifact cannot be accepted as-is.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no external assets, frameworks, bundlers, or build tools.**  
  All server code, HTML, CSS, and browser JavaScript are contained in `app.ts`. Bun directly serves the application and no external network calls or dependencies are used.

- **PASS — TLS is configured using the required mkcert certificate paths.**  
  `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`, and session cookies use the `Secure` attribute.

- **PASS — Mobile-responsive and legible SPA UI.**  
  The UI includes a mobile viewport declaration, constrained responsive layout, large form controls, visible focus states, semantic headings, labels, forms, error regions, and accessible status messaging.

- **PASS — Authentication and MFA ownership are server-enforced.**  
  MFA provisioning, confirmation, recovery-code verification, and regeneration require an authenticated server session bound to `marcus-account-001`. Client-provided account identity fields are explicitly rejected.

- **PASS — Session handling includes secure cookies, rotation, expiration, and logout invalidation.**  
  The session cookie is `HttpOnly`, `Secure`, `SameSite=Strict`, path-scoped, and has no user data. Sessions rotate after sign-in and identity verification, enforce idle and absolute expiry, and are removed on logout.

- **PASS — CSRF protections apply to state-changing requests.**  
  State-changing API calls require a session-bound CSRF token. The implementation also uses `SameSite=Strict` cookies and checks request origins against a trusted-origin allow-list.

- **PASS — Security headers and restrictive CORS are present.**  
  The app sends CSP with nonces, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, restrictive permissions policy, no-referrer policy, and only emits CORS headers for trusted origins.

- **PASS — Input validation and output handling are implemented.**  
  Email, phone, OTP, recovery-code, and manual-secret values are validated server-side. No database is used, so parameterized-query requirements are not applicable. Dynamic secret and recovery-code DOM rendering uses `textContent`.

- **PASS — OTP secrets and recovery codes are protected at rest.**  
  Draft and enrolled MFA secrets are AES-GCM encrypted with a process-only cryptographic key. Recovery codes are generated with `crypto.getRandomValues`, salted, SHA-256 hashed, and plaintext recovery codes are not retained server-side.

- **PASS — Authenticator setup supports manual entry and browser-visible test values.**  
  The provisioning endpoint returns a manual RFC 6238 secret and a current test OTP. The browser logs the identity code, setup key, test OTP, and issued recovery codes as required for mock testing.

- **PASS — Identity verification and recovery-code verification are time-bound/rate-limited.**  
  Identity codes expire after three minutes, and repeated failures lock the identity flow. Recovery-code verification tracks failed attempts and locks after the configured threshold. Recovery codes are marked used after successful validation.

- **FAIL — MFA TOTP confirmation is not guaranteed single-use under concurrent requests.**  
  `/api/mfa/confirm` checks `draft.used` before asynchronous decryption and TOTP validation, but only sets `draft.used = true` after those awaited operations. Two concurrent requests using the same valid setup secret and TOTP can both pass the initial check, both validate, and both return successful recovery-code responses. This violates the single-use verification requirement.

- **FAIL — Recovery-code issuance can become inconsistent under concurrent MFA confirmation.**  
  Because two concurrent `/api/mfa/confirm` requests can both reach `issueRecoveryCodes`, each can return a different plaintext recovery-code set. Only whichever request last writes `session.recoveryCodes` remains active. The other successful response gives the user recovery codes which are immediately invalid.

- **PASS — Errors are generic and do not expose server stack traces or secrets.**  
  Server failures return a generic JSON error body, and the outer request handler catches unexpected errors without returning exception details.

- **PASS — No browser persistence of sensitive values.**  
  The client keeps CSRF tokens, provisioning data, and issued recovery codes only in JavaScript memory. It does not use `localStorage`, `sessionStorage`, or non-HttpOnly cookies.

## FAILING_ITEMS

- **MFA confirmation is vulnerable to a concurrent-request race condition.**  
  `draft.used` is checked before `await decryptDraftSecret(...)` and `await validTotp(...)`, then marked used only after validation. Multiple concurrent valid requests can therefore consume the same setup draft/TOTP more than once.

- **Concurrent MFA confirmations can return recovery-code sets that do not match the final server state.**  
  Each successful concurrent confirmation independently calls asynchronous `issueRecoveryCodes`. Multiple successful responses may expose different code sets, while only the final assignment to `session.recoveryCodes` is usable.

## NEW_TASKS

1. **Make `/api/mfa/confirm` atomic per session.**  
   Add a server-side in-progress/reserved state to `Draft` or use a per-session mutex. Reserve the draft synchronously before the first `await`; reject any simultaneous confirmation attempt. Clear the reservation only when validation fails, expires, or errors.

2. **Ensure recovery-code issuance occurs exactly once for a successfully confirmed draft.**  
   Within the same atomic confirmation section, mark the draft consumed and generate/store one recovery-code set before returning it. Ensure later or concurrent requests cannot overwrite `session.recoveryCodes` or return a second successful code set.

3. **Add a regression test/manual verification scenario for concurrent confirmation.**  
   Send two simultaneous valid `POST /api/mfa/confirm` requests using the same CSRF token, setup secret, and TOTP. Verify exactly one returns success and exactly one recovery-code set becomes active.

## DECISION

FAIL