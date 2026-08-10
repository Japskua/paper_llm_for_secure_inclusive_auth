## SUMMARY

The artifact is a valid single-file Bun HTTPS SPA with strong baseline security controls: TLS configuration, CSP nonce usage, secure cookies, CSRF validation, random one-time reset tokens, bcrypt password hashing, throttling, authorization checks, and safe DOM rendering. However, the client-side state is never refreshed after successful sensitive operations, which prevents the recovery flow from progressing past token verification. There are also access-control and session-lifetime weaknesses that conflict with the stated security requirements.

## FUNCTIONAL_CHECK

- **PASS — Single-file delivery and zero-compilation compliance.**  
  The server, HTML, CSS, and vanilla browser JavaScript are contained in one `app.ts`. No frameworks, bundlers, external assets, network calls, or compilation pipeline are used.

- **PASS — Bun HTTPS server uses the specified local certificates.**  
  `Bun.serve()` is configured with `certs/cert.pem` and `certs/key.pem`, binds to `localhost`, and does not create a separate plaintext HTTP listener.

- **PASS — HTTPS/security response headers are substantially configured.**  
  The HTML response includes HSTS, CSP with a per-response nonce, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, and no-store caching headers.

- **PASS — CSRF protection is implemented for state-changing API operations.**  
  Sessions receive random CSRF tokens, and every `POST` API handler checks `X-CSRF-Token` before processing the request.

- **PASS — Session cookies use appropriate browser protections.**  
  The session cookie uses the `__Host-` prefix, `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, and has no `Domain` attribute.

- **PASS — Reset tokens are random, short-lived, and single-use.**  
  Recovery tokens are generated with cryptographic randomness, expire after 10 minutes, are compared in a timing-safe manner, and are marked used after successful verification.

- **PASS — Token and MFA brute-force attempts are throttled.**  
  Recovery-token and MFA-code failures are blocked for one minute after five failed attempts.

- **PASS — Password policy and hashing are implemented.**  
  Passwords require at least 12 characters with uppercase, lowercase, numeric, and symbol characters. Passwords are hashed with bcrypt via `Bun.password.hash()` and are not logged or returned.

- **PASS — Sensitive backend actions enforce state-based authorization.**  
  Password reset requires verified recovery state, privacy acceptance requires authentication, and appointment confirmation requires both authentication and privacy acceptance.

- **PASS — The UI mitigates DOM XSS.**  
  Dynamic UI content is created through DOM APIs and inserted with `textContent`; it does not interpolate untrusted data into `innerHTML`.

- **PASS — Recovery token supports both simulated link and manual submission.**  
  The API returns a mock recovery link/token, the browser logs it, the link can populate the verification form, and the token may also be entered manually.

- **PASS — Browser-side mock delivery logging is implemented.**  
  The recovery token/link and mock MFA code are logged using browser `console.log()` and are also displayed in the local Logs panel.

- **FAIL — The password recovery flow cannot progress after recovery-token verification.**  
  The browser obtains `session` only once during initial load. After `/api/recovery/verify` succeeds, the server sets `state.resetAuthorized = true`, but the client still has stale `session.resetAuthorized === false`. `go("reset")` invokes `render()`, which redirects the user back to the recovery page. The same stale-state defect also breaks navigation from reset to MFA, MFA to privacy, privacy to appointment, and appointment to confirmation.

- **FAIL — Recovery request feedback is hidden from the user.**  
  In `renderRecovery`, `status.hidden = true` is set initially, but the submit callback changes only `status.textContent` and `status.className`; it never sets `status.hidden = false`. Consequently, the required clear response is not visually shown after a recovery request.

- **FAIL — A recovery request for any syntactically valid identifier creates a reset token for the protected account.**  
  `/api/recovery/request` validates only identifier syntax. Every syntactically valid email/identifier receives a recovery token whose server state points to `accountRef: "protected-account"`. Therefore, an arbitrary visitor can submit any valid-looking identifier, receive a usable reset token, set a new password, and complete the deterministic MFA flow. This does not prevent unauthorized password resets.

- **FAIL — Server-side session expiration is not enforced.**  
  The cookie has `Max-Age=1800`, but session records in `sessions` have no expiry timestamp and `sessionFor()` accepts any session ID that remains in the map. A copied or manually replayed session cookie can remain valid on the server indefinitely, beyond the browser cookie lifetime.

## FAILING_ITEMS

- Client authorization state is stale after all successful state-changing API calls. This makes the intended end-to-end recovery, password reset, MFA, privacy acceptance, and appointment confirmation flow unusable.
- The recovery-request status element remains hidden after submission, so users do not receive visible confirmation or error feedback.
- Recovery issuance is not bound to a recognized/eligible account or a secure simulated ownership check; any valid-format identifier produces credentials for the sole protected account.
- Session validity depends only on browser cookie expiration, not server-side expiration. The server retains and honors expired session IDs indefinitely.

## NEW_TASKS

1. Add a client-side `refreshSession()` function that calls `/api/session`, updates `csrf` and `session`, and invoke it after every successful sensitive API request before calling `go(...)` (`verify`, `reset-password`, `mfa/verify`, `privacy/accept`, and `appointment/confirm`).

2. In the recovery form submit handler, set `status.hidden = false` before displaying the API result so recovery feedback is visible.

3. Change recovery issuance so a syntactically valid identifier does not automatically authorize reset of `protected-account`. Use server-side account eligibility/ownership logic; retain the same generic response for unknown identifiers, and limit testing-token delivery to an explicitly controlled mock recovery scenario rather than arbitrary submitted identifiers.

4. Add `expiresAt` to `SessionState`, set it when creating sessions, reject and delete expired sessions in `sessionFor()`, and align server-side expiration with the cookie `Max-Age`.

## DECISION

**FAIL**