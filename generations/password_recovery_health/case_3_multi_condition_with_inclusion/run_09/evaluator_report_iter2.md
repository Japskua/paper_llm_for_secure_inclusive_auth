## SUMMARY

The artifact is a well-structured single-file Bun HTTPS SPA with inline vanilla JavaScript, a clear multi-step recovery UX, CSRF protections, session cookies, CSP nonces, rate limiting, bcrypt hashing for updated passwords, and browser-console delivery simulations. However, it does not fully meet the security and UX requirements: the reset initiation response leaks whether the submitted email matches the mock account, and an initial account password is hardcoded in plaintext in the server source. The saved-progress messaging is also misleading because local progress can outlive the server-side recovery session.

## FUNCTIONAL_CHECK

- **PASS — Single-file delivery and zero-compilation compliance.**  
  The server, HTML, CSS, and browser JavaScript are contained in `app.ts`. It uses Bun directly, has no framework, no bundler, no external assets, and no external network calls.

- **PASS — Bun HTTPS server uses the supplied certificate paths.**  
  The server checks for and loads `certs/cert.pem` and `certs/key.pem`, then starts `Bun.serve` with TLS enabled.

- **PASS — Password recovery flow is implemented end-to-end.**  
  The UI supports recovery request, manual reset-token entry, new-password selection, MFA confirmation, password update, sign-in, and privacy acceptance.

- **PASS — Recovery token is random, session-bound, single-use, and short-lived.**  
  Reset tokens are generated with `randomBytes`, are 64 hexadecimal characters, expire after 15 minutes, are tied to the current session, and are invalidated after password update.

- **PASS — Manual verification-code entry is supported.**  
  The recovery token is displayed in the browser Logs panel and browser console for testing, and the user can manually paste/type it into the confirmation field.

- **PASS — Simulated delivery and verification messages are logged in the browser.**  
  Client-side `console.log` calls log the reset token, MFA code, and verification outcomes. The Logs panel also renders these messages safely with `textContent`.

- **PASS — CSRF protections are implemented for sensitive POST actions.**  
  A cryptographically random per-session CSRF token is created server-side, returned through bootstrap, and validated with `timingSafeEqual` for POST API routes.

- **PASS — Session cookies have appropriate core protections.**  
  The session cookie is `Secure`, `HttpOnly`, `SameSite=Strict`, path-scoped, and has a server-side expiration check.

- **PASS — Secure response headers are configured.**  
  The implementation sets HSTS, CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, and no-store cache headers.

- **PASS — XSS protections are generally sound.**  
  Dynamic browser content is inserted using DOM APIs and `textContent`, not `innerHTML`. The inline script is protected by a per-document CSP nonce. No user-controlled values are injected into HTML markup.

- **PASS — Password policy and password hashing are implemented for reset passwords.**  
  New passwords require at least 12 characters with uppercase, lowercase, number, and symbol. Updated passwords are hashed with Bun bcrypt before storage.

- **PASS — MFA is implemented in the recovery flow.**  
  A six-digit simulated MFA code is required after reset-token confirmation and before the password can be updated.

- **PASS — Sensitive action rate limiting is implemented.**  
  Recovery initiation, token checks, MFA checks, password updates, and login requests are rate limited and temporarily blocked after repeated attempts.

- **PASS — The interface addresses several ADHD/inclusivity requirements.**  
  It provides numbered progress steps, short instructions, visible feedback, a help section at every stage, calm wording, focus indicators, and local step persistence.

- **FAIL — Recovery initiation leaks account existence.**  
  The server claims to return a generic response to prevent account enumeration, but `/api/recovery/initiate` includes `testDeliveryToken` only when the submitted email exactly matches `RECOVERY_EMAIL`. An attacker can submit candidate addresses and determine which one maps to the mock account by checking whether `testDeliveryToken` exists.

- **FAIL — A password is stored as plaintext in source code.**  
  `InitialMockPassword!2025` is embedded as a plaintext password literal and hashed at startup. This conflicts with the requirement that passwords must never be stored in plaintext. The initial mock password should be represented by a precomputed bcrypt hash or removed from the design.

- **FAIL — “Pause and return” behavior is not reliably preserved as communicated.**  
  The UI stores the step locally, but recovery state is server-session-bound and expires after 24 hours. A user can return with local storage indicating Step 2–6 while the server no longer has the recovery/authentication state. The UI may then show a later step that cannot succeed, without automatically restarting or clearly explaining why.

- **FAIL — The UI falsely states that the MFA code does not expire.**  
  Step 4 says, “This practice code does not expire,” but the MFA verification is dependent on the recovery object, whose reset-token expiration is enforced at 15 minutes. This is misleading and conflicts with the requirement for clear, low-stress feedback.

## FAILING_ITEMS

- `/api/recovery/initiate` exposes `testDeliveryToken` only for `helena@example.test`, allowing direct account enumeration despite the generic message.
- The literal `InitialMockPassword!2025` is a plaintext password in `app.ts`.
- Client-side saved progress is not reconciled with server-side session/recovery state after expiration, session loss, server restart, or use from a different browser context.
- Step 4 incorrectly tells users that the safety code does not expire even though recovery state expires after 15 minutes.

## NEW_TASKS

1. Remove the account-enumeration signal from `/api/recovery/initiate`; ensure successful initiation responses have the same JSON shape and observable behavior for valid and invalid email addresses while retaining a safe, explicitly test-only mechanism for browser-console token simulation.
2. Replace the hardcoded initial plaintext password with a precomputed bcrypt hash, or redesign the mock account so no plaintext seed password exists in source code.
3. Add bootstrap/session-state reconciliation: return the server-authoritative recovery/authentication stage and reset the client to the appropriate safe step when saved local state is no longer valid.
4. Replace the incorrect “This practice code does not expire” text with accurate, calm guidance explaining that the recovery process is available for a limited period and that requesting a new code is always possible.

## DECISION

**FAIL**