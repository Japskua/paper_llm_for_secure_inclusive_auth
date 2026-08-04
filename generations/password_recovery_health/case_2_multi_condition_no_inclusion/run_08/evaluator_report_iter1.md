## SUMMARY

The artifact is a valid single-file Bun/TypeScript HTTPS SPA with inline vanilla HTML/CSS/JS, CSP nonces, session-bound CSRF protection, secure cookies, token hashing, password hashing with bcrypt, throttling, MFA simulation, and a functional recovery-to-privacy-acceptance flow. However, it does not fully meet the explicit requirement that password reset tokens be **single-use**: a valid token can be successfully verified repeatedly until it expires or the password is saved.

## FUNCTIONAL_CHECK

- **PASS — Single-file, zero-compilation implementation**
  - The server, HTML template, CSS, and client-side JavaScript are all contained in `app.ts`.
  - It uses Bun directly via `Bun.serve` and does not require a bundler, framework, external assets, or external network calls.

- **PASS — HTTPS and security headers**
  - Bun is configured with the supplied `certs/cert.pem` and `certs/key.pem`.
  - Responses include HSTS, CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, restrictive referrer/permissions policies, cache prevention, and cross-origin isolation headers.
  - The session cookie is `Secure`, `HttpOnly`, and `SameSite=Strict`.

- **PASS — CSRF protection for state-changing actions**
  - A cryptographically random CSRF token is generated per session.
  - All POST API routes require `X-CSRF-Token` validation against the active session.
  - State-changing requests use same-origin credentials and JSON POST requests.

- **PASS — Access control and session binding**
  - Recovery, verification, password update, MFA, privacy acceptance, and confirmation are bound to the current session.
  - The confirmation endpoint checks the required recovery, MFA, and privacy-acceptance state before returning success.
  - No patient records, usernames, course folders, or other private identifiers are exposed.

- **PASS — XSS/injection defenses**
  - Account input, reset tokens, and passwords are validated server-side.
  - Dynamic client-side output uses `textContent`, not HTML interpolation.
  - Query-string values are not server-rendered.
  - CSP uses a fresh nonce for the trusted inline style and script blocks.

- **FAIL — Reset tokens are random and short-lived, but not fully single-use**
  - Reset tokens are cryptographically random, hashed before storage, session-bound, and expire after ten minutes.
  - However, after a successful `/api/verify-token` request, the token remains valid and may be verified repeatedly until password submission or expiry.
  - The explicit requirement says password reset tokens must be “single-use.” A successful verification should consume the token immediately while preserving a separate, short-lived authorization state for the password-update step.

- **PASS — Password policy and password storage**
  - Passwords require 12–128 non-space characters with uppercase, lowercase, numeric, and symbol characters.
  - Passwords are stored only as bcrypt hashes using `Bun.password.hash`.
  - Plaintext passwords are not stored or returned.

- **PASS — Brute-force protections**
  - Reset-token verification and MFA verification block further attempts for one minute after five failures.
  - The user receives clear throttling feedback.

- **PASS — MFA and simulated delivery**
  - A deterministic mock MFA code is returned by the server and logged in the browser as required for evaluation.
  - MFA is required before privacy-condition acceptance.
  - The recovery token is also returned to the UI, logged in the browser console, and can be entered manually.

- **PASS — Safe authentication and phishing guidance**
  - The UI warns users not to share passwords, recovery links, or verification codes.
  - It states that hospital staff will not request these secrets by email or phone.
  - No outgoing URLs, redirects, or external network requests are accepted from user input.

- **PASS — Internal navigation and recovery-link behavior**
  - The recovery flow supports manually entering a token.
  - `/reset?stage=verify&token=...` opens the verification stage and prepopulates the supplied valid token.
  - All SPA stages have working navigation controls.

## FAILING_ITEMS

- **Password reset tokens are not consumed at successful verification.**
  - In `/api/verify-token`, a successful token check only sets `active.tokenVerified = true`.
  - `active.resetUsed` remains `false`, and `active.resetTokenHash` remains present.
  - Therefore, the same token can be submitted successfully multiple times before expiry or password saving, which does not satisfy the stated single-use-token requirement.

## NEW_TASKS

1. Add a separate session field for a consumed reset token / authorized password-reset state, such as `resetTokenConsumed: boolean`, and initialize it to `false` when creating or restarting a recovery request.

2. On successful `/api/verify-token` validation, immediately mark the token as consumed and clear `resetTokenHash`, while retaining only a short-lived verified-reset authorization state needed by `/api/password`.

3. Update `tokenCurrentlyValid` and `/api/password` so password saving requires the short-lived verified-reset authorization state rather than the still-stored reset token hash.

4. Ensure subsequent submissions of the same reset token fail after the first successful verification, while a newly issued recovery token resets the consumed/verified state correctly.

## DECISION

FAIL