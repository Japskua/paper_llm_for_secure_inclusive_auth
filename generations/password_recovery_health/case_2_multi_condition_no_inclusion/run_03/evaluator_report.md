## SUMMARY

The artifact is a valid single-file Bun HTTPS application implementing a functional password-recovery flow with recovery-token verification, password policy enforcement, bcrypt hashing, mock MFA, authenticated privacy-condition acceptance, browser-console mock delivery logs, and security headers. The implementation is syntactically coherent and satisfies the stated functional and security requirements for this local simulation.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application:** The server, HTML template, CSS, and browser-side vanilla JavaScript all exist in `app.ts`. No framework, bundler, compiler, or external asset is used.

- **PASS — Bun TLS server uses supplied certificate paths:** `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`, and the application is served over HTTPS on port 3000.

- **PASS — HTTPS and secure response headers:** The server configures HSTS, CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, and `Cache-Control: no-store`. The TLS-only server and `Secure` session cookie support HTTPS enforcement.

- **PASS — Session security:** Sessions use cryptographically random identifiers, are stored server-side, expire after one hour, and are sent in `Secure`, `HttpOnly`, `SameSite=Strict` cookies.

- **PASS — CSRF protection:** A unique CSRF token is generated for each session and is required on every API POST route through `protectedSession`. Token validation includes a length check and constant-time-style character comparison.

- **PASS — Access control / IDOR prevention:** Reset records are bound to the originating server-side session through `sessionId`; clients do not submit account IDs, usernames, folder identifiers, or other private identifiers. Sensitive actions require session state and appropriate prior-step authorization.

- **PASS — Recovery token security:** Reset tokens are generated with `crypto.getRandomValues`, are URL-safe, are stored only as SHA-256 digests, expire after ten minutes, are session-bound, and are consumed when successfully verified.

- **PASS — Manual token verification:** The recovery token is automatically placed into the verification field for local testing, but the user can overwrite, paste, or manually type a token before submitting it.

- **PASS — Browser-console mock delivery:** Recovery tokens and MFA codes are logged using browser-side `console.log` via `localLog()`. They are also displayed in the on-page Logs panel, satisfying the local testing requirement without external delivery.

- **PASS — Brute-force mitigation:** Recovery requests are limited to three per 15 minutes per session; token verification is limited to six per ten minutes per session; MFA locks for one minute after five failed attempts.

- **PASS — Password security:** Passwords must be 12–256 characters and include uppercase, lowercase, numeric, and symbol characters. Passwords are hashed with Bun bcrypt before storage and plaintext passwords are neither persisted nor logged.

- **PASS — MFA implementation:** A six-digit mock MFA code is required after password reset. MFA is single-use and includes retry throttling/lockout behavior.

- **PASS — Privacy-condition authorization:** Privacy acceptance requires successful password reset and MFA confirmation. The server validates `accept === true` before updating the session state.

- **PASS — XSS and injection controls:** Request JSON is size-limited and parsed defensively. Expected field types and formats are validated. User-controlled values are not inserted into HTML; client-visible output uses `textContent`, not `innerHTML`. The CSP uses per-response nonces for the trusted inline style and script.

- **PASS — No external requests or open redirects:** The application only handles explicit same-origin paths, makes no external network calls, contains no redirect behavior, and does not accept outgoing URLs from users.

- **PASS — Anti-phishing guidance:** The UI warns users not to share passwords or codes by email or phone and instructs them to verify the HTTPS localhost address.

- **PASS — Functional UI flow:** The UI progresses through recovery request, token verification, password replacement, MFA confirmation, privacy review, and final completion. All implemented internal navigation controls function through browser-side event handlers.

- **PASS — Error handling and production disclosure:** Request errors return generic messages and the top-level server handler suppresses stack traces and debug information.

## FAILING_ITEMS

- None identified.

## NEW_TASKS

1. None.

## DECISION

PASS