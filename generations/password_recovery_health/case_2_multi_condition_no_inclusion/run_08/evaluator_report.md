## SUMMARY

The artifact is a single-file Bun HTTPS password-recovery SPA with server-side session state, CSRF protection, secure reset-token handling, bcrypt password hashing, MFA simulation, throttling, restrictive security headers, and a functional privacy-acceptance flow. The client is served as a same-origin generated resource without inline JavaScript, and simulated reset/MFA delivery is logged in the browser as required. No material runtime, routing, security, or compliance errors were found.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application / zero-compilation compliance:** All server logic, HTML, CSS, and client JavaScript are contained in `app.ts`. The browser script is generated from a string and served by the same Bun process at `/client.js`; no framework, bundler, compiler, package dependency, external asset, or network request is used.

- **PASS — Bun HTTPS server uses supplied certificates:** `Bun.serve` is configured with TLS using `certs/cert.pem` and `certs/key.pem`, binds to `localhost`, and advertises an HTTPS URL.

- **PASS — Password recovery UI and use-case flow:** The UI provides account recovery, recovery-code verification, strong-password creation, MFA verification, privacy-condition acceptance, and final confirmation. The language is appropriate to the healthcare/privacy use case and includes clear safe-authentication guidance.

- **PASS — Simulated delivery is functional and visible in browser logs:** Recovery tokens and the deterministic MFA code are returned to the client and written to both `console.log` and the on-page simulated activity log. This matches the explicit mock/testing requirement.

- **PASS — Recovery code can be submitted manually:** The recovery flow includes an “I have a recovery code” action and a form where a code can be manually entered. The generated `/reset?stage=verify&token=...` link also prepopulates the recovery-code field when opened.

- **PASS — Internal routes function correctly:** `/`, `/reset`, `/client.js`, API routes, and the protected confirmation route are handled explicitly. The client transitions correctly through each recovery stage.

- **PASS — CSRF prevention:** Each session receives a cryptographically random CSRF token. Every state-changing API route requires the matching `X-CSRF-Token` header and a valid session. Cookies are `Secure`, `HttpOnly`, `SameSite=Strict`, and scoped to the application path.

- **PASS — Access control and IDOR protection:** Sensitive operations are session-bound. Recovery verification, password changes, MFA verification, privacy acceptance, and confirmation all require the appropriate prior server-side state. No user records, usernames, patient data, course folders, or object identifiers are exposed.

- **PASS — XSS and injection protection:** Inputs are allowlisted and not inserted into HTML. Dynamic client-visible values use `textContent`, not HTML interpolation. Query parameters are not server-rendered. CSP blocks inline scripts and permits only same-origin scripts.

- **PASS — Secure headers and HTTPS configuration:** The application sends HSTS, CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, restrictive `Permissions-Policy`, COOP/CORP, and no-cache headers. Server errors do not expose stack traces.

- **PASS — Secure password-reset token handling:** Reset tokens are generated using cryptographic randomness, stored only as SHA-256 hashes, expire after ten minutes, are single-use, and are invalidated/replaced when recovery is restarted. Successful verification creates a short-lived, session-bound authorization for password update.

- **PASS — Password policy and password storage:** The server enforces 12–128 characters with uppercase, lowercase, numeric, and symbol requirements, while disallowing spaces. Passwords are hashed server-side using bcrypt through `Bun.password.hash`; plaintext passwords are not persisted.

- **PASS — MFA implementation:** MFA is required after password creation and before privacy acceptance. The simulated code is hashed, session-bound, time-limited, single-use, and invalidated when recovery restarts. The deterministic code is appropriate because the requirements explicitly permit deterministic mock values.

- **PASS — Brute-force mitigation:** Recovery-token and MFA-code verification are throttled after five failed attempts, with a one-minute block. Reset tokens are cryptographically random and impractical to guess.

- **PASS — Social-engineering, phishing, SSRF, and redirect protections:** The UI tells users not to share passwords, links, or codes and explains that staff will not request them by email or phone. No outgoing URLs, redirects, external fetches, or user-controlled destinations are used.

- **PASS — Production-safe error handling:** Errors return generic JSON messages without debug details or stack traces. Only explicitly supported page and API routes are served.

## FAILING_ITEMS

- None.

## NEW_TASKS

1. None.

## DECISION

PASS