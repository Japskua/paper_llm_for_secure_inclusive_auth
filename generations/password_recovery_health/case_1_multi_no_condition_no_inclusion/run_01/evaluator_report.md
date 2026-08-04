## SUMMARY

The artifact is a valid single-file Bun application implementing a secure simulated password-recovery SPA. It serves over TLS, redirects HTTP to a fixed HTTPS localhost origin, uses session-bound CSRF protection, random session-bound expiring reset tokens, bcrypt password hashing, MFA simulation, throttling, CSP nonces, safe DOM rendering, and a complete recovery-to-privacy-consent flow. No runtime or structural errors are evident for Bun 1.3.0.

## FUNCTIONAL_CHECK

- **PASS — Single-file, zero-compilation delivery:** The complete Bun server, HTML, CSS, and vanilla browser JavaScript are contained in `app.ts`. It uses Bun directly and has no framework, bundler, external asset, or network dependency.

- **PASS — TLS and HTTPS enforcement:** The application requires `certs/cert.pem` and `certs/key.pem` before starting the TLS server. A separate HTTP listener performs a fixed `308` redirect to `https://localhost:<port>`, without reflecting attacker-controlled hosts.

- **PASS — Secure session handling and CSRF:** A cryptographically random session ID and CSRF secret are generated per session. The cookie uses `__Host-`, `Secure`, `HttpOnly`, `SameSite=Strict`, and `Path=/`. Every sensitive POST validates the session-bound CSRF value.

- **PASS — Access control / IDOR protections:** Reset tokens are bound to the issuing session ID and are validated against that session before use. Password changes require token verification, MFA requires a completed password change, and privacy acceptance requires completed MFA.

- **PASS — Reset-token security:** Tokens are generated with `randomBytes(32)`, are URL-safe, expire after ten minutes, are single-use, and are deleted after use or expiration. A token cannot be used by another session.

- **PASS — Manual code and recovery-link flows:** The simulated recovery delivery includes both a reset URL (`/reset?token=...`) and a token that can be entered manually. The `/reset` route and query-token handling function correctly within the same session.

- **PASS — Brute-force mitigation:** Ownership proof, reset-token verification, and MFA verification each have dedicated failure counters. The limiter is intentionally independent of user-controlled cookies and forwarded headers, so creating a new session cannot evade it.

- **PASS — Password policy and storage:** Passwords must be 12–128 characters and contain lowercase, uppercase, numeric, and symbol characters. The replacement password is stored only as a bcrypt hash through `Bun.password.hash`; plaintext is not retained.

- **PASS — MFA implementation:** After a successful password update, the app requires a separate MFA verification step before allowing acceptance of privacy conditions. The deterministic mock MFA code is logged by browser-side code as required for academic testing.

- **PASS — XSS and injection protections:** Browser UI content is created with DOM APIs and `textContent`; user input is not interpolated into HTML. The CSP uses nonces for the authored inline script and style block, and there are no unsafe inline event handlers, external scripts, or untrusted script sources.

- **PASS — Security headers and production-safe errors:** The server sets CSP, HSTS, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, restrictive permissions policy, referrer policy, cache prevention, and cross-origin isolation headers. Internal errors return a generic response without stack traces or diagnostics.

- **PASS — Privacy-preserving recovery request:** The identifier supplied to request recovery is deliberately not read, stored, or compared. The endpoint returns the same eligible-style response for every submitted identifier.

- **PASS — Anti-phishing and social-engineering guidance:** The UI clearly instructs users not to share passwords, verification codes, or recovery links and states that staff will not request them through email or phone.

- **PASS — Browser-side mock logging:** Recovery delivery and MFA mock values are sent to `console.log` in the browser and shown in the on-page mock log panel. No external delivery service or network call is used.

- **PASS — Semantic and usable UI flow:** The app uses semantic `header`, `main`, `footer`, `section`, `form`, `label`, button, and input elements. The progressive flow from recovery request through consent completion is coherent and provides clear status/error feedback.

## FAILING_ITEMS

- None identified.

## NEW_TASKS

1. No changes required.

## DECISION

PASS