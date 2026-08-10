## SUMMARY

The artifact is a valid single-file Bun HTTPS SPA implementing the requested password-recovery, password-reset, sign-in, and privacy-acceptance flow. It uses vanilla HTML/CSS/JS, provides browser-console simulated delivery values, uses session-scoped CSRF protection, TLS, security headers, random expiring single-use reset tokens, bcrypt password hashing, MFA verification, throttling, output-safe DOM rendering, and clear ADHD-oriented progress/help UI.

## FUNCTIONAL_CHECK

- **PASS — Single-file `app.ts` delivery:** Server logic, HTML template, CSS, and browser JavaScript are all contained in the provided `app.ts`.
- **PASS — Bun direct execution / no compilation:** The code is Bun-compatible TypeScript and uses `Bun.serve` directly, without bundlers, frameworks, build tooling, or external assets.
- **PASS — HTTPS/TLS configuration:** The server loads `certs/cert.pem` and `certs/key.pem` and serves only with `tls` configured. Session cookies are marked `Secure`.
- **PASS — Security response headers:** HSTS, CSP with a per-page nonce, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, and no-store cache controls are configured.
- **PASS — CSRF protection:** A random CSRF token is created per session and checked using constant-time comparison on every state-changing POST route.
- **PASS — Session protection/access control:** Session IDs are random, server-side, constrained to expected format, expire after one day, and use `HttpOnly`, `Secure`, and `SameSite=Strict` cookies. Privacy acceptance is session-scoped and requires authentication.
- **PASS — Sensitive-route access checks:** Password updates require valid recovery verification and MFA verification; privacy acceptance requires an authenticated session.
- **PASS — Random, short-lived, single-use reset token:** Reset tokens use `randomBytes`, expire after 15 minutes, are validated server-side, and are consumed before successful verification returns.
- **PASS — Manual recovery-token submission:** The UI provides a manual input field for the recovery token and validates it through `/api/recovery/verify-token`.
- **PASS — Browser-only simulated delivery logging:** The client logs the reset token and MFA code with `console.log`, and also displays them in the on-page Logs section for the practice system.
- **PASS — Strong password policy:** Both client and server enforce at least 12 characters containing uppercase, lowercase, numeric, and symbol characters.
- **PASS — Secure password storage:** Updated passwords are hashed server-side using Bun bcrypt (`Bun.password.hash(... algorithm: "bcrypt")`) and authentication uses bcrypt verification.
- **PASS — MFA present in recovery flow:** The reset flow requires a six-digit simulated MFA/safety code before the password can be saved.
- **PASS — Brute-force mitigation:** Recovery initiation, token verification, MFA verification, password update, and authentication endpoints are rate-limited and temporarily blocked after excessive attempts.
- **PASS — XSS protections:** User-controlled content is inserted into the DOM through `textContent`; user input is not interpolated into HTML, script, URLs, or server-rendered markup.
- **PASS — No external calls / SSRF exposure:** There are no outgoing fetches, webhooks, redirects, URL parameters, or user-controlled outbound URL handling.
- **PASS — Anti-phishing/social-engineering guidance:** The help panel explicitly tells users not to share passwords or security codes and states that staff will not request them by email.
- **PASS — ADHD/inclusivity UX:** The UI has visible numbered progress, one primary task per screen, simple wording, persistent session-stage recovery after refresh, a prominent help section, no client-side countdown, and no unexpected navigation.
- **PASS — Internal navigation/functionality:** The SPA flow transitions correctly through request, token confirmation, password selection, MFA, sign-in, privacy acceptance, and completion without relying on nonfunctional links.
- **PASS — Error handling / production behavior:** Request parsing is guarded, unexpected request errors return a generic message, and stack traces/debug data are not exposed.

## FAILING_ITEMS

- None identified.

## NEW_TASKS

1. No remediation tasks required.

## DECISION

PASS