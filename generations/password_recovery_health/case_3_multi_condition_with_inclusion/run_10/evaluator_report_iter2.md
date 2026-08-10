## SUMMARY

The artifact is a well-structured single-file Bun HTTPS application with a functioning guided recovery flow, CSRF protection, CSP nonces, bcrypt password hashing, MFA simulation, password policy enforcement, and safe DOM rendering. However, it does not fully meet the security requirements because its throttling is only per session and can be bypassed by creating a new session, and server-side sessions have no enforced expiry despite the cookie expiry. These issues affect brute-force protection and session security.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no build tools or external assets.**  
  `app.ts` contains the Bun server, HTML, CSS, and browser-side vanilla JavaScript. It uses no framework, bundler, compiler, external CDN, or network calls.

- **PASS — HTTPS server uses the supplied certificate paths.**  
  The server reads `certs/cert.pem` and `certs/key.pem` and configures Bun TLS through `Bun.serve({ tls: { cert, key } })`.

- **PASS — Password recovery flow is functional and complete.**  
  The flow supports recovery request, manual recovery-code verification, verification-link verification, MFA confirmation, password change, login, and privacy-condition confirmation.

- **PASS — Manual code submission is supported in addition to the verification link.**  
  `/api/verify` accepts either `body.code` or `body.token`, and the client provides both a manual-code form and a verification-link action when a token is in the URL.

- **PASS — Recovery simulation is visible in the browser console and UI log.**  
  The browser-side `say()` function calls `console.log()` and safely appends messages to the visible log list. The recovery token, verification URL, and MFA code are logged in the browser.

- **PASS — Reset tokens are cryptographically random, single-use, and short-lived.**  
  `randomValue(32)` generates the reset token, `resetUsed` prevents reuse, and `resetExpires` limits the reset transaction to ten minutes.

- **PASS — Passwords are not stored in plaintext.**  
  Passwords are hashed and verified using Bun bcrypt APIs: `Bun.password.hash(..., { algorithm: "bcrypt" })` and `Bun.password.verify(...)`.

- **PASS — Strong password policy is enforced.**  
  Password changes require 12–128 characters and uppercase, lowercase, numeric, and symbol characters. Matching confirmation is also required.

- **PASS — MFA is implemented.**  
  A second confirmation-code step is required after recovery-token verification and before the password can be changed.

- **FAIL — Brute-force protection is not sufficient against new-session bypasses.**  
  Attempt tracking is stored only in `session.attempts`. An attacker can obtain a fresh session by omitting/clearing the cookie and avoid the five-attempt block. This does not adequately mitigate automated guessing or provide an account-level lockout as required.

- **PASS — CSRF tokens are unique per session and checked on mutation endpoints.**  
  Sessions receive a random `csrf` token, and all POST API routes pass through `csrfValid()` before actions are processed.

- **PASS — Sensitive actions enforce state-based access control.**  
  Password change requires the verified MFA state; login requires the password-changed state and the account bound to the recovery session; privacy confirmation requires authenticated state.

- **PASS — XSS defenses are generally sound.**  
  User-provided values are not interpolated into HTML. Browser-side messages are inserted with `textContent`, and the page uses a restrictive nonce-based CSP.

- **PASS — Secure headers are configured.**  
  Responses include HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and no-store cache controls.

- **FAIL — Server-side session expiry is not enforced.**  
  The cookie has `Max-Age=1800`, but the `sessions` map retains sessions indefinitely and `getSession()` accepts any known session ID without checking an expiry timestamp. Cookie expiration is client-controlled and does not prevent a stolen or manually replayed old session ID from remaining valid server-side.

- **PASS — The UI supports low-stress, structured progression.**  
  It provides visible progress, one-step instructions, predictable transitions, restart controls, help content, clear success/error feedback, and non-sensitive local progress reminders.

- **PASS — No private account identifiers are exposed through UI/API responses.**  
  Account IDs and identifiers remain server-side. Recovery responses are generic with respect to whether an identifier maps to a real account.

## FAILING_ITEMS

- **Per-session-only rate limiting can be bypassed.**  
  `allowed()` and `recordFailure()` use `session.attempts`, which means clearing cookies or starting a new browser session resets the attempt counter. There is no shared account-level, identifier-level, or source-IP-based protection for recovery, MFA, password, or login attempts.

- **Sessions do not have server-enforced expiration.**  
  `Session` has no `createdAt`, `expiresAt`, or idle-expiry fields. The server retains session objects in the global `sessions` map indefinitely and accepts them as long as their ID remains in that map, regardless of the cookie’s `Max-Age`.

## NEW_TASKS

1. Add server-side session lifetime enforcement: store creation and expiry timestamps in `Session`, reject and delete expired sessions in `getSession()`, and periodically or opportunistically remove expired entries from `sessions`.

2. Replace session-only authentication throttling with shared throttling keyed by a safe server-side key such as account ID/normalized identifier plus source IP, with an account-level temporary lockout or escalating delay after repeated failed login, MFA, and recovery-verification attempts.

## DECISION

**FAIL**