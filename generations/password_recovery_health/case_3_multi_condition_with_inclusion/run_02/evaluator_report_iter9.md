## SUMMARY

The artifact is a strong single-file Bun implementation with a clear, ADHD-friendly multi-step recovery flow, session-bound CSRF protection, HTTPS/TLS configuration, CSP nonces, Argon2id password hashing, MFA simulation, token expiry/single-use handling, and browser-side mock logging. However, it does not fully meet the brute-force protection requirement for reset-token verification, and it generates a verification link without presenting that link to the user in the UI. These gaps prevent acceptance.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun server and SPA implementation**
  - The complete server, HTML, CSS, and browser JavaScript are contained in `app.ts`.
  - It uses `Bun.serve` directly and does not require a bundler, framework, compiler pipeline, or external assets.

- **PASS — TLS/HTTPS configuration**
  - The server uses `certs/cert.pem` and `certs/key.pem` through Bun TLS configuration.
  - HSTS is returned on responses.
  - The application rejects requests indicating `x-forwarded-proto: http`.

- **PASS — Security headers and CSP**
  - The response includes HSTS, CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, COOP, and no-store cache headers.
  - The CSP uses a per-page nonce for the embedded stylesheet and client script.
  - User-provided values are rendered using `textContent`, not unsafe HTML insertion.

- **PASS — Session handling and CSRF protections**
  - Sessions are server-side, random, expiry-bound, and stored in an `HttpOnly`, `Secure`, `SameSite=Strict`, `__Host-` cookie.
  - Sensitive POST routes require both a same-origin `Origin` header and the session-specific CSRF token.
  - The CSRF token is generated uniquely when each session is created.

- **PASS — Password reset token security**
  - Reset tokens are generated randomly.
  - Only SHA-256 hashes of reset tokens are stored server-side.
  - Tokens expire after 15 minutes and are marked used after a successful password replacement.
  - Reused and expired tokens are rejected.
  - Reset-token URLs work in a new browser session, and manual token entry is supported.

- **FAIL — Automated guessing / brute-force mitigation for reset-token confirmation**
  - `/api/recovery/instruction` has no effective rate limit or lockout for invalid reset-token submissions.
  - `tokenFailures` and `tokenLockUntil` are defined in the reset-token record but are never incremented or enforced meaningfully for invalid token guesses.
  - An attacker can send unlimited invalid reset-token values to this endpoint from one session. Although token entropy is high, this does not satisfy the explicit requirement that automated guessing attempts be throttled or blocked.

- **PASS — Login and MFA brute-force mitigation**
  - Login failures are tracked per account hash and locked after five failures.
  - Recovery identity, MFA code, and MFA possession-value checks apply failure counters and lockouts.
  - MFA has an expiry period and requires two distinct simulated values before authentication is granted.

- **PASS — Strong password policy and password hashing**
  - Passwords require at least 12 characters with uppercase, lowercase, numeric, and symbol characters.
  - Passwords are hashed using `argon2id` via `Bun.password.hash`.
  - Plaintext passwords are not stored.

- **PASS — Access control for privacy and appointment actions**
  - Privacy acceptance requires an authenticated, completed MFA session.
  - Appointment confirmation requires completed MFA and accepted privacy conditions.
  - Sensitive server state is not addressable through user-controlled object identifiers, avoiding an obvious IDOR path.

- **PASS — XSS and injection handling**
  - Inputs are validated server-side.
  - Browser log/UI output uses `textContent`.
  - No user input is inserted with `innerHTML`, evaluated as code, or used in redirects.
  - No external URLs or network calls are made.

- **PASS — ADHD-inclusive UX flow**
  - The UI gives visible numbered progress, a “Current step” reminder, low-density cards, clear feedback, optional help, and no forced timeout in the browser flow.
  - State can be resumed while the server session remains valid.
  - The content uses plain, consistent language and separates the task into manageable steps.

- **FAIL — Recovery verification link is not actually presented in the UI**
  - The recovery API returns `deliveryPath`, but the client ignores it.
  - The user is never shown a clickable simulated recovery link, despite the server implementing support for `/?recovery-test=...`.
  - The user can manually submit the token and the token is logged, but the generated link is not visibly delivered through the UI. This weakens the simulated delivery flow and makes the link functionality undiscoverable.

- **PASS — Browser-side mock delivery logging**
  - The reset token, recovery identity value, MFA demonstration code, and possession value are logged through browser-side `console.log`.
  - They are also displayed in the on-page log area for testability and user orientation.

- **PASS — No external calls, redirects, or exposed private account data**
  - The application makes only same-origin API calls.
  - No user account identifiers are returned from recovery API responses.
  - Recovery responses do not reveal whether an entered account exists.

## FAILING_ITEMS

- **Reset-token confirmation is not brute-force throttled.**
  - Invalid requests to `/api/recovery/instruction` can be attempted indefinitely.
  - The declared `tokenFailures` / `tokenLockUntil` fields do not protect unknown or invalid token submissions because no endpoint-level/session-level failure tracking is implemented.

- **The simulated recovery link is generated but not delivered in the visible UI.**
  - `deliveryPath` is included in the successful recovery-request response but never rendered as a safe same-origin link.
  - The backend link route works, but users cannot access it through the normal recovery UI.

## NEW_TASKS

1. Add a session-scoped reset-token confirmation failure counter and lockout in `/api/recovery/instruction`; increment it for malformed, unknown, expired, or used token submissions and reject additional attempts for a defined cooldown after the threshold.

2. Reset the reset-token confirmation failure counter after a successful token confirmation.

3. Render the successful `deliveryPath` from `/api/recovery/request` as a visible, same-origin simulated recovery link in the recovery-instruction feedback area, using safe DOM APIs such as `document.createElement("a")`, `textContent`, and a validated relative path.

## DECISION

**FAIL**