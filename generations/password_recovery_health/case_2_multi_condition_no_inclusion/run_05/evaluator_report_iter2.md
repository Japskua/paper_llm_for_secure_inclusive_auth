## SUMMARY

The artifact is a well-structured single-file Bun password-recovery SPA with TLS, CSP nonces, server-side sessions, CSRF validation, throttling, bcrypt password hashing, MFA simulation, and a functional recovery-to-appointment flow. However, it has a startup failure-handling defect: when TLS certificates are absent, it sets `process.exitCode` but leaves a referenced `setInterval` running, so the process does not actually exit. Because the application claims to fail closed and terminate in this case, this must be corrected.

## FUNCTIONAL_CHECK

- **Single `app.ts` artifact containing Bun server, HTML, CSS, and vanilla browser JavaScript: PASS**
  - The server and the complete client SPA template are contained in the supplied `app.ts`.
  - No framework, bundler, external asset, or external network request is used.

- **Bun serves the application directly with no compilation/build tooling: PASS**
  - The implementation uses `Bun.serve()` directly and embeds client code in the returned HTML.

- **TLS/HTTPS enforcement using `certs/cert.pem` and `certs/key.pem`: FAIL**
  - The HTTPS server correctly uses the required certificate paths when they exist.
  - However, when certificates do not exist, `process.exitCode = 1` does not terminate the process because `setInterval(removeExpiredSessions, ...)` has already been started and keeps the event loop active.
  - This leaves a non-serving process running indefinitely rather than cleanly failing/terminating as the startup message states.

- **HTTP traffic redirects to a fixed HTTPS destination: PASS**
  - Port `8080` only returns a fixed `308` redirect to `https://localhost:3000/`.
  - There is no user-controlled redirect target or open redirect.

- **Security headers and caching controls: PASS**
  - The HTTPS application responses set HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options`, referrer policy, permissions policy, and no-store cache controls.
  - CSP uses a per-response nonce for the intentionally embedded style and script blocks.

- **CSRF protection and server-side sensitive-action enforcement: PASS**
  - A cryptographically random CSRF token is generated per session.
  - POST API requests require both same-origin `Origin` validation and CSRF token validation.
  - Privacy acceptance and appointment booking are controlled by server-owned authenticated/session state, preventing client-side phase skipping.

- **Session security and access control: PASS**
  - Session IDs are random and stored server-side.
  - Cookies are `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, and satisfy the `__Host-` cookie constraints.
  - Sensitive phases are enforced server-side, mitigating IDOR-style phase manipulation.
  - Expired sessions are rejected on lookup.

- **Recovery tokens are secure, short-lived, and single-use: PASS**
  - Reset tokens are cryptographically random, opaque, time-limited, and invalidated after successful verification.
  - Token comparisons use timing-safe comparison after strict format validation.

- **Brute-force mitigation: PASS**
  - Recovery, token verification, MFA verification, password validation, and sign-in actions have per-session failed-attempt tracking and temporary blocking after five failures.

- **Password policy and password storage: PASS**
  - Passwords require at least 12 characters, upper/lowercase letters, a number, and a symbol.
  - Common/repetitive passwords are rejected.
  - Passwords are hashed with bcrypt using `Bun.password.hash`; plaintext passwords are not retained or logged.

- **MFA and recovery simulation: PASS**
  - The flow requires a recovery token followed by a six-digit MFA code before password reset.
  - The reset token and MFA code are returned only within the simulated browser session and are logged via browser-side `console.log`, as required for testing.

- **Manual verification-code submission: PASS**
  - The UI provides manual fields for both the recovery token and MFA code.

- **XSS/injection protection: PASS**
  - Client-rendered dynamic content is assigned through `textContent`, `value`, and DOM node APIs rather than `innerHTML`.
  - Server input validation is strict for account values, reset tokens, MFA codes, and passwords.
  - CSP restricts scripts to the server-issued nonce.

- **No patient/private identifiers exposed: PASS**
  - The UI intentionally avoids displaying patient records, usernames, appointment identifiers, or account existence information.
  - Recovery responses are generic with respect to account validity.

- **Phishing/social-engineering guidance: PASS**
  - The recovery and password pages warn users not to share passwords through email or support contacts and to verify the local hospital address.

- **End-to-end UX flow for privacy acceptance and appointment request: PASS**
  - The SPA implements recovery, token verification, MFA, password reset, sign-in confirmation, privacy acceptance, appointment confirmation, and completion states.
  - Server-side phase checks prevent navigating directly to sensitive completion actions.

## FAILING_ITEMS

- **TLS-missing startup path does not actually exit.**
  - `setInterval(removeExpiredSessions, SESSION_CLEANUP_MS);` is invoked before the TLS availability check.
  - When certificates are missing, the code only sets `process.exitCode = 1`; the live interval prevents Bun from naturally terminating.
  - The process therefore remains running even though it logs that the secure portal was “NOT STARTED.”

## NEW_TASKS

1. Move `setInterval(removeExpiredSessions, SESSION_CLEANUP_MS)` into the `else` branch after TLS certificates have been validated and the secure servers are started, or explicitly call `process.exit(1)` when TLS certificates are unavailable.

## DECISION

**FAIL**