## SUMMARY

The artifact is a well-structured single-file Bun HTTPS application with a guided password-reset UI, server-side sessions, CSRF validation, CSP/security headers, bcrypt hashing, MFA simulation, route/state authorization, and browser-console delivery logs. However, the primary manual recovery-code flow is broken: the UI logs the reset token as the “manual recovery code,” but the verification endpoint will not accept that token when it is entered into the code field. This prevents the required manual-code recovery path from working as presented. The finite 10-minute reset lifetime and 30-minute session lifetime also conflict with the stated no-timeout/pause-and-return UX requirement.

## FUNCTIONAL_CHECK

- **PASS — Single-file application and zero-build compliance:** The complete Bun server, HTML, CSS, and browser JavaScript are contained in `app.ts`. It uses Bun directly with no framework, bundler, external assets, or network calls.

- **PASS — HTTPS with provided certificates:** The server reads `certs/cert.pem` and `certs/key.pem` and configures Bun TLS. The recovery URL uses `https://localhost:3000`.

- **PASS — Guided, low-distraction recovery UX:** The UI provides visible progress, one task per screen, “Next step” reminders, persistent help guidance, restart controls, accessible labels, restrained styling, and clear success/error messaging.

- **FAIL — Manual recovery-code submission works correctly:** The UI logs `result.resetToken` as the “manual recovery code” and asks the user to enter it in the recovery-code field. However, form submission sends `{ code: code.value }`, while the server validates `body.code` only against `session.manualCode` (`RECOVERY-DEMO-482913`), not against `session.resetToken`. The displayed/logged random reset token therefore fails manual verification.

- **FAIL — Simulated delivery data is consistently available in the browser console:** The reset token and verification URL are logged in the browser, but the actual server-accepted manual code (`RECOVERY-DEMO-482913`) is neither returned by `/api/recovery-request` nor logged by the browser. The UI instructs the user to use a delivered code that was not actually delivered.

- **PASS — Verification-link flow works:** The reset token in `/verify?token=...` is read from the URL and submitted as `{ token: linkToken }`, which matches `session.resetToken`. The token is random, session-bound, expires after 10 minutes, and is invalidated after use.

- **PASS — Reset token security:** Reset tokens are generated with cryptographically secure random bytes, expire after a short lifetime, are bound to a server session, and are marked unusable after verification.

- **PASS — CSRF protections:** Sensitive POST routes require the per-session CSRF token. The session cookie is `Secure`, `HttpOnly`, and `SameSite=Strict`; CSRF tokens are validated server-side for mutations.

- **PASS — Authentication and authorization controls:** State-changing endpoints check required prior stages. Password change requires verified recovery plus MFA. Privacy confirmation requires an authenticated session. The account identifier is not returned by APIs.

- **PASS — Password security:** Passwords are bcrypt-hashed using `Bun.password.hash`, never intentionally logged, and must meet a 12-character policy requiring uppercase, lowercase, numeric, and symbol characters.

- **PASS — MFA implementation:** The reset flow requires a second confirmation step after recovery verification. The deterministic MFA test code is returned and logged in the browser as required for the simulated environment.

- **PASS — Brute-force mitigation:** Recovery verification, MFA, password changes, recovery requests, and login attempts have server-side failure tracking keyed by action, identifier, and source IP, with escalating delays.

- **PASS — XSS and injection resistance:** Inputs are format-validated server-side. The browser constructs dynamic UI with DOM APIs and `textContent`, rather than injecting user-controlled HTML. The CSP restricts script execution to a response-specific nonce.

- **PASS — Secure headers and caching controls:** HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options`, restrictive `Permissions-Policy`, `Referrer-Policy`, and no-store cache headers are configured.

- **PASS — No direct identifier exposure or account enumeration:** Recovery requests use a sink account for unknown identifiers and return the same outward recovery progression, avoiding direct disclosure of whether an account exists.

- **FAIL — Pause/return flow fully meets the no-timeout requirement:** The UI says the process “does not rush or time out while you are using the page,” but server state expires after 30 minutes and the recovery token expires after 10 minutes. Local storage only saves a generic stage reminder; it cannot restore an expired server-side recovery flow. A short-lived reset token is appropriate for security, but the UI must not imply no timeout and should provide a forgiving reissue/resume behavior.

## FAILING_ITEMS

- The manual recovery-code flow is internally inconsistent and fails in the normal UI:
  - `/api/recovery-request` creates both `session.resetToken` and `session.manualCode`.
  - The response returns only `resetToken`.
  - The browser logs `resetToken` as the manual code.
  - The manual verification form sends that value as `code`.
  - `/api/verify` only accepts `code` when it equals `session.manualCode`, not when it equals `session.resetToken`.

- The actual deterministic manual recovery code is never delivered to the browser console or UI, despite the UI stating that the user should use the delivered recovery code.

- The interface promises no timeout while the server enforces a 10-minute reset-token expiry and a 30-minute session expiry. Saved local progress does not make it possible to continue the expired flow.

## NEW_TASKS

1. Fix the manual recovery-code contract by choosing one consistent approach:
   - return `manualCode: TEST_RECOVERY_CODE` from `/api/recovery-request` and log that value in the browser, **or**
   - accept `body.code` when it matches `session.resetToken`, so the reset token displayed by the current UI can be entered manually.
   
2. Update the recovery-request browser log and verification-screen help text so they accurately identify the value accepted by the manual verification form.

3. Revise the timeout UX so it does not claim that recovery “does not rush or time out.” Keep the reset token short-lived for security, but provide an explicit, low-stress “request a fresh code and continue” recovery path when a token/session has expired, and explain that only the code expires rather than implying progress is silently lost.

## DECISION

**FAIL**