## SUMMARY

The artifact is a valid single-file Bun application implementing a simulated password-recovery flow with HTTPS, session-bound CSRF protection, random single-use reset tokens, MFA verification, rate limiting, bcrypt password hashing, security headers, and browser-console mock delivery. The UI flow and internal navigation function without external assets, frameworks, build tools, or network calls.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun server and client application:** All server logic, HTML, CSS, and vanilla browser JavaScript are contained in `app.ts`. No framework, bundler, compiler, or external asset is used.
- **PASS — HTTPS/TLS configuration:** `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`, as required for the supplied mkcert certificates.
- **PASS — Secure session handling:** Sessions use cryptographically random identifiers, are stored server-side, expire after 30 minutes, and are issued via `HttpOnly`, `Secure`, `SameSite=Strict` cookies.
- **PASS — CSRF protection:** Every POST API action requires a session-bound CSRF token in `X-CSRF-Token`; requests without a valid session/token receive a 403 response.
- **PASS — Access-control enforcement / IDOR prevention:** Recovery tokens are bound to the originating session and a fixed internal account binding. Token verification, MFA, password changes, and privacy acceptance enforce the required prior state.
- **PASS — Password-reset token security:** Reset tokens are generated using `crypto.getRandomValues`, are stored only as SHA-256 hashes, expire after 10 minutes, are session-bound, and are marked single-use immediately upon successful verification.
- **PASS — Manual token entry and recovery-link support:** The user may enter a token manually in the token form. A `?token=` recovery link automatically initiates verification and fills the token field.
- **PASS — Browser-side deterministic mocks:** The browser logs the recovery token, local verification link, and deterministic MFA code through `console.log`, while also displaying them in the local Logs panel. No server-side mock-delivery logging is used.
- **PASS — MFA implementation:** A second verification step is required after a valid token and before password reset. The deterministic local test code works as intended.
- **PASS — Brute-force throttling:** Recovery requests, token verification, MFA attempts, and password-related attempts are rate-limited with lockouts after repeated failures.
- **PASS — Strong password policy:** Passwords must be 12–128 characters and include uppercase, lowercase, numeric, and symbol characters.
- **PASS — Password hashing:** New passwords are hashed with Bun’s bcrypt support and are not logged or returned in plaintext.
- **PASS — XSS/injection protections:** User-controlled values are not injected into server-rendered HTML. Browser UI messages are assigned with `textContent`, not `innerHTML`. CSP uses a per-response nonce and blocks arbitrary scripts.
- **PASS — Secure response headers:** The application configures HSTS, CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, and no-store cache headers.
- **PASS — No external network calls or open redirects:** Browser requests are limited to same-origin API routes. Recovery links are local relative paths; no user-controlled external URLs are accepted or followed.
- **PASS — Privacy-acceptance workflow:** Privacy conditions can only be accepted after successful token verification, MFA, and password update.
- **PASS — Safe authentication guidance:** The UI advises users never to share passwords, reset tokens, or MFA codes and warns against external credential links.
- **PASS — Semantic and accessible UI basics:** The page uses semantic sections, forms, labels, headings, live status regions, and navigation controls.

## FAILING_ITEMS

- None.

## NEW_TASKS

1. None.

## DECISION

**PASS**