## SUMMARY

The artifact is a valid single-file Bun application with a clear, accessible recovery UI, TLS configuration, CSP/nonces, per-session CSRF protection, Argon2id password hashing, and working simulated reset/MFA flows. However, it fails critical authorization and brute-force protections: any visitor can reset the single global password using any syntactically valid email, and MFA/reset-verification attempts are not throttled. The pause-and-return behavior also does not preserve recovery progress as required.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun implementation with no bundler, compiler, framework, or external assets.**  
  The server, HTML, CSS, and browser JavaScript are all contained in `app.ts`. Bun directly serves the page, and there are no external network calls or asset dependencies.

- **PASS — TLS is configured to use the required certificate paths.**  
  `Bun.serve` uses `certs/cert.pem` and `certs/key.pem`, matching the required certificate locations.

- **PASS — The recovery UI is a functional SPA with semantic structure and clear step guidance.**  
  The UI uses `header`, `main`, `section`, labels, progress indicators, live status messaging, and an orderly sequence of reset, verification, password creation, sign-in, MFA, and privacy acceptance.

- **PASS — Reset-token delivery is simulated in the browser and manual code entry works.**  
  `/api/request-reset` returns a token, and browser-side `demoLog()` writes the token and constructed recovery URL to both the browser console and visible demo log. The user can manually enter the code in the recovery-code field.

- **PARTIAL/FAIL — Recovery-link UX is incomplete.**  
  The application constructs a recovery URL and prints it as plain text in a `<pre>` element, but does not render it as a clickable internal link. The `/?token=...` route itself works if manually opened, but the visible “recovery link” cannot be opened directly from the application.

- **FAIL — Password recovery prevents unauthorized access.**  
  The reset-request endpoint accepts **any syntactically valid email address**, does not check whether it belongs to an account, does not associate the reset token with an account, and resets one global `passwordHash`. Consequently, any unauthenticated visitor can request a reset token for arbitrary input such as `attacker@example.com`, receive it in their own browser, and reset Helena’s password. This is a critical authorization failure.

- **PASS — CSRF protections are implemented for sensitive POST requests.**  
  A cryptographically random CSRF token is generated per server session, returned only to the same session, included by the client in every POST request, and validated server-side. The session cookie is `HttpOnly`, `Secure`, and `SameSite=Strict`.

- **PASS — Core output handling avoids reflected/stored XSS.**  
  User input is not interpolated into HTML. Browser output uses `textContent`, and server-generated HTML does not inject request data. CSP uses per-response nonces for the inline application script/style.

- **PASS — Security headers and HTTPS-oriented settings are present.**  
  The app sets HSTS, CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, `Cache-Control: no-store`, secure cookies, and a restrictive CSP.

- **PASS — Reset tokens are cryptographically random, short-lived, and invalidated after password reset.**  
  Tokens use 32 random bytes, expire after 15 minutes, and are deleted/marked used following a successful password change.

- **FAIL — Automated guessing protections are incomplete.**  
  Login attempts are throttled after five failures, but `/api/verify-reset` and `/api/mfa` have no rate limiting, attempt counting, lockout, or delay. In particular, the MFA code is a fixed six-digit value (`246810`) and can be repeatedly guessed without restriction.

- **PASS — Password hashing and baseline password policy are implemented.**  
  Passwords are hashed with Argon2id via `Bun.password.hash`. The policy requires at least 12 characters and lowercase, uppercase, numeric, and symbol characters.

- **FAIL — Password input is silently modified before hashing and verification.**  
  Passwords are passed through `text()`, which trims whitespace and truncates values to 300 characters. A user entering a password with intentional leading/trailing spaces will not actually save the password they entered. Password values must be validated without mutation.

- **PASS — MFA exists and gates the authenticated privacy action.**  
  A password login creates an MFA challenge, `/api/mfa` sets `session.authenticated = true` only after the correct code, and `/api/privacy` checks authentication before accepting the privacy statement.

- **PASS — No open redirects, SSRF paths, or external URL fetching are present.**  
  The app does not fetch arbitrary URLs, does not accept redirect targets, and does not expose external navigation functionality.

- **PASS — Safe-authentication guidance and help are available.**  
  The “Need help?” control works and advises users that hospital staff will not request their password or recovery code.

- **FAIL — Pause-and-return behavior does not preserve recovery progress.**  
  Although `hospitalRecoveryStep` is written to `localStorage`, on reload `initialize()` intentionally returns the user to the start screen and says they must restart the recovery check. This conflicts with the requirement to allow users to pause and return without losing progress. It also does not restore the safe server-side recovery state after successful token verification.

- **PASS — The code is syntactically plausible for Bun 1.3.0 and has no obvious runtime API misuse.**  
  `Bun.serve`, `Bun.file`, `Bun.password.hash`, and `Bun.password.verify` are used in supported patterns. The unused `readFileSync` import is not a functional runtime error, though it should be removed.

## FAILING_ITEMS

- Any unauthenticated user can reset the global account password because `/api/request-reset` accepts any valid email and reset tokens are not bound to a real account or verified recipient.
- The app models only one global password hash, rather than account-specific authentication/recovery state.
- `/api/verify-reset` has unlimited token-verification attempts and no throttling.
- `/api/mfa` has unlimited attempts against a deterministic six-digit MFA code and no expiry, lockout, or rate limiting.
- Passwords are silently trimmed and truncated by `text()`, changing user credentials instead of validating the exact submitted value.
- Reloading the page discards the current recovery step and forces the user to restart, violating the required pause/resume experience.
- The displayed recovery URL is plain log text rather than an operable internal recovery hyperlink.
- `readFileSync` is imported but unused.

## NEW_TASKS

1. Replace the global-password model with a minimal mock account record keyed by a normalized, recognized account email; only issue a reset token for that account while returning a generic response for unknown emails.
2. Bind every reset-token record to its intended account identifier and update only that account’s password hash during `/api/reset-password`.
3. Add per-session and/or per-token failed-attempt tracking, rate limiting, and temporary lockout for `/api/verify-reset`.
4. Add MFA-code expiration plus per-session MFA attempt limits and temporary lockout/rate limiting for `/api/mfa`.
5. Stop using `text()` for passwords; read password and confirmation as raw strings, reject oversized passwords explicitly, and compare/hash the unmodified values.
6. Add a safe recovery-status endpoint backed by server session state, and use it on initialization to resume the appropriate non-secret step without storing passwords or reset tokens in `localStorage`.
7. Render the simulated recovery URL as a same-origin clickable `<a>` element created with safe DOM APIs, while retaining manual recovery-code entry.
8. Remove the unused `readFileSync` import.

## DECISION

FAIL