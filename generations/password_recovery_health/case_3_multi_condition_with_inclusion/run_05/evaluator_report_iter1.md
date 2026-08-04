## SUMMARY

The artifact is a single-file Bun HTTPS SPA with a clear, accessible password recovery UI and a mostly functional recovery → password → MFA → privacy-acceptance flow. It correctly uses browser-side DOM APIs safely, TLS configuration, CSP nonces, CSRF tokens, secure cookies, bcrypt hashing for newly submitted passwords, and simulated browser-console delivery codes. However, it does not fully meet the security and continuity requirements: recovery can reset the shared demo account for any valid identifier, rate limits are trivially bypassed by creating a new session, the initial password is embedded in plaintext source, recovery-request progress is not actually preserved after a refresh, and reset-token consumption has a concurrency race.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no framework, bundler, compiler, or external assets.**  
  `app.ts` contains the Bun server, HTML, CSS, and browser-side vanilla JavaScript. It uses no external assets or network calls.

- **PASS — HTTPS/TLS server configuration.**  
  Bun is configured with `certs/cert.pem` and `certs/key.pem`, and the application listens through a TLS-enabled Bun server. HSTS is configured on normal responses.

- **PASS — Functional recovery journey and internal recovery link.**  
  The normal flow works: recovery request creates a token, the code can be manually entered, `/recovery-link?token=...` opens the same recovery UI, a password can be changed, MFA can be completed, and privacy conditions can be accepted.

- **PASS — Simulated delivery values are made available in the browser.**  
  The recovery token and MFA code are returned to the UI and logged through browser-side `console.log`, allowing deterministic testing and manual code entry.

- **FAIL — Recovery flow prevents unauthorized password reset.**  
  `/api/recovery` accepts any syntactically valid identifier and always creates a reset record for the same global `DEMO_ACCOUNT_KEY`. An attacker can submit any valid string, receive a reset token in their own browser response, and change `accountPasswordHash`, which represents the shared account. This does not enforce ownership of the recovery destination/account.

- **FAIL — Recovery state is preserved when pausing and returning.**  
  The UI claims that “secure server progress remains available,” but after requesting a recovery code, refreshing or returning later normally returns the user to the start screen. The server stores no `recoveryRequested` phase and the browser only keeps `rememberedLinkToken` in memory. The user must find the token again or request a new one, contrary to the pause-and-return requirement.

- **PASS — Clear, structured, low-distraction, ADHD-aware UX.**  
  The step indicator, one-action-per-screen layout, plain language, no countdown, visible help area, safe-authentication reminders, and pause option all substantially satisfy the inclusivity requirements.

- **PASS — CSRF protection for state-changing routes.**  
  Sessions receive a random CSRF token, and POST API routes validate `X-CSRF-Token`. Cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`.

- **FAIL — Brute-force protections are not effective across sessions.**  
  Login, recovery, verification, password, and MFA limits are keyed only by `session.id`. An attacker can clear cookies or create fresh sessions to bypass every limit immediately. This does not adequately throttle automated guessing attempts.

- **PASS — Password policy and bcrypt usage for updated passwords.**  
  New passwords require 12+ characters, upper/lowercase, a number, a symbol, and no spaces. Submitted replacement passwords are stored using Bun bcrypt hashing.

- **FAIL — Password is present in plaintext in application source.**  
  `Initial!Hospital2026` is hardcoded as plaintext and then hashed at startup. This conflicts with the requirement that passwords must never be stored in plaintext. A bcrypt hash should be stored/configured instead.

- **FAIL — Reset tokens are not safely consumed under concurrent requests.**  
  In `/api/password`, the server checks `reset.used`, then awaits bcrypt hashing, and only afterward sets `reset.used = true`. Two concurrent requests using the same verified token can both pass the `used` check before either awaits completes, allowing both to update the password. This violates reliable single-use token enforcement.

- **PASS — XSS/injection defenses in the client UI.**  
  User-derived strings are not interpolated into HTML. UI rendering uses `textContent`, `createElement`, and controlled DOM construction. Inputs are validated, and a nonce-based CSP restricts scripts.

- **PASS — Security headers and clickjacking protections on normal application responses.**  
  CSP, HSTS, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and no-store caching are configured for normal responses.

- **FAIL — Secure headers are missing on the server error response.**  
  The `error()` handler returns only `Cache-Control`, omitting HSTS, CSP, anti-framing, MIME-sniffing, and referrer headers. Error responses should preserve the secure header baseline.

- **PASS — No IDOR-style resource routes or SSRF/open redirect mechanism are exposed.**  
  There are no user-addressable private resource IDs, outbound URL fetches, redirect parameters, or server-side URL handling routes.

- **PASS — MFA and anti-phishing guidance are implemented.**  
  The flow requires MFA after reset/sign-in and prominently tells users to verify the HTTPS site and never share passwords or codes by phone/email. The deterministic MFA code is acceptable for the stated mock/testing context.

- **FAIL — Requirement that all simulated mock logging occur in the browser is not fully followed.**  
  The browser correctly logs delivery values, but the server also emits simulated-delivery/MFA/handoff `console.log` messages. The requirement explicitly states that all mocks must use `console.log` in the browser.

## FAILING_ITEMS

- Any valid identifier can request a token that resets the shared demo account; recovery is not bound to an account-owned delivery channel or safely scoped mock account.
- Recovery-request progress is not retained across refresh/return, despite the pause UI promising that secure progress remains available.
- Rate limiting is only session-based and can be bypassed by starting a new session.
- The initial password is hardcoded in plaintext in `app.ts`.
- A reset token can be consumed by concurrent password-update requests because `used` is marked after an awaited password hash operation.
- The global error handler does not return the same secure response headers as normal routes.
- Mock-related server-side `console.log` calls conflict with the requirement that mocks be logged in the browser.

## NEW_TASKS

1. Replace the global, identifier-agnostic recovery behavior with a safe mock account model: validate that the requested identifier maps to an approved mock account and issue a reset token only for that account/session’s simulated delivery path; do not let arbitrary identifiers reset the shared password state.

2. Add a server-side recovery-request phase to `Session` so that, after a refresh or pause, `/api/status` returns enough non-sensitive state to resume at “Check your recovery code” without requiring the user to restart.

3. Change brute-force tracking to include a stable attacker/account dimension, such as source IP plus action and/or account key, in addition to session ID; enforce limits for login, recovery, token verification, password updates, and MFA across newly created sessions.

4. Remove `Initial!Hospital2026` from source and initialize the account with a precomputed bcrypt hash or a securely supplied test secret that is never stored as plaintext in `app.ts`.

5. Make reset-token consumption atomic before any awaited operation in `/api/password`, so only one request can reserve and use a reset token; ensure invalid password submissions can still be retried safely without incorrectly consuming the token.

6. Update the Bun `error()` handler to return the same HTTPS/security-header baseline as other responses, including HSTS, CSP, frame protections, MIME-sniffing protection, referrer policy, and no-store caching.

7. Remove simulated-delivery, simulated-MFA, and simulated-handoff `console.log` calls from the server; retain the required mock-code logging exclusively in the browser-side script.

## DECISION

**FAIL**