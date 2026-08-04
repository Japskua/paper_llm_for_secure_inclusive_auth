## SUMMARY

The artifact is a valid single-file Bun 1.3.0 HTTPS password-recovery SPA. It serves inline HTML/CSS/vanilla browser JavaScript from `app.ts`, uses the provided TLS certificate paths, and implements a complete recovery → verification/MFA → password update → privacy acceptance flow. The code includes strong security controls appropriate to the deterministic mock requirement, including session-bound CSRF protection, CSP nonces, secure cookies, rate limiting, Argon2id password hashing, short-lived single-use reset tokens, input validation, and safe DOM rendering.

## FUNCTIONAL_CHECK

- **PASS — Single-file application and no compilation/build tooling:** The Bun server, HTML template, CSS, and browser JavaScript are all contained in `app.ts`. No framework, bundler, external asset, or network dependency is used.

- **PASS — Bun TLS server uses the required certificate locations:** The server reads `certs/cert.pem` and `certs/key.pem`, refuses to start if either is absent, and configures them in `Bun.serve({ tls: ... })`.

- **PASS — HTTPS enforcement and secure response headers:** The application is served only through the TLS-enabled Bun server. It sets HSTS, CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, and `Cache-Control: no-store`.

- **PASS — CSRF prevention:** Each server-side session receives a cryptographically random CSRF token. Every state-changing API request requires matching same-origin `Origin`, `X-CSRF-Token`, and JSON-body CSRF values.

- **PASS — Session controls:** Session identifiers are random, server-side, `HttpOnly`, `Secure`, `SameSite=Strict`, and time-limited. Expired sessions are rejected and periodically cleaned up.

- **PASS — Sensitive action authorization / IDOR prevention:** Password changes require a short-lived, session-bound recovery grant, and privacy-condition acceptance requires an authenticated session. No user-controlled object identifiers or private-resource routes are exposed.

- **PASS — No private identifiers exposed:** The UI does not reveal usernames, patient data, course folders, or account-existence information. Reset-request messaging is generic.

- **PASS — XSS/injection protections:** User-controlled values are not interpolated into HTML. Dynamic messages are assigned using `textContent`, inputs are allow-list validated, JSON is strictly parsed, and CSP restricts executable scripts to server-generated nonce-bearing scripts.

- **PASS — Trusted inline script handling:** Although the single-file requirement necessitates inline browser logic, the script and stylesheet are protected by a unique CSP nonce generated per HTML response. There are no untrusted or dynamically loaded scripts.

- **PASS — Reset token security:** Reset tokens are generated with cryptographically secure randomness, stored only as SHA-256 hashes server-side, bound to the session, short-lived, and invalidated immediately after successful verification.

- **PASS — Manual recovery-code submission and verification-link behavior:** The recovery token is included in the local hash route for convenient verification, and the verification screen also provides a manually editable recovery-code field.

- **PASS — Mock delivery is visible in the browser console:** The client-side `log()` function calls `console.log()`. The generated reset token and deterministic MFA code are logged in the browser, satisfying the testing/mock-delivery requirement.

- **PASS — MFA is implemented for the mock flow:** Verification requires both the random reset token and deterministic six-digit mock MFA code (`246810`).

- **PASS — Brute-force mitigation:** Sensitive actions are limited to five attempts per session per 60-second window, returning HTTP 429 after the threshold is reached.

- **PASS — Strong password policy:** New passwords require at least 14 characters and must include lowercase, uppercase, numeric, and symbol characters. Input length is also bounded.

- **PASS — Password hashing:** Passwords are hashed with Bun’s Argon2id implementation before storage. No plaintext password is persisted in server state.

- **PASS — Clear token and recovery feedback:** The UI and API report invalid, expired, malformed, mismatched, or rate-limited recovery attempts without exposing sensitive backend details.

- **PASS — No open redirects or SSRF behavior:** The application has no outgoing network calls and does not accept destination URLs. Verification routing uses only a validated local fragment value.

- **PASS — Anti-phishing guidance:** Each recovery-flow screen informs users that hospital staff will not ask for passwords or recovery codes by email or telephone.

- **PASS — Internal navigation works:** Hash-based navigation correctly renders the recovery, verification, password creation, and privacy-confirmation screens. Server-side authorization still protects actions if users manually navigate to later hash routes.

- **PASS — Code validity:** The TypeScript/Bun APIs used are compatible with the stated Bun runtime model: top-level `await`, `Bun.file`, `Bun.password.hash` with Argon2id, `Bun.serve` TLS configuration, Web Crypto APIs, and browser-side vanilla JavaScript are used appropriately.

## FAILING_ITEMS

- None identified.

## NEW_TASKS

1. No changes required.

## DECISION

PASS