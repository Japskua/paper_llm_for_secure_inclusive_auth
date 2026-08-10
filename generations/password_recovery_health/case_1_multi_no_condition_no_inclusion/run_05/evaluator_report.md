## SUMMARY

The artifact is a single-file Bun/TypeScript password-recovery SPA with server-side session, CSRF, reset-token, MFA, password-update, login, and privacy-acceptance handling. It uses HTTPS/TLS, secure response headers, bcrypt password hashing, rate limits, server-side authorization checks, and browser-side simulated delivery logging. The code appears syntactically valid for Bun 1.3.0 and meets the specified functional and security requirements.

## FUNCTIONAL_CHECK

- **PASS — Single-file delivery:** All server logic, HTML, CSS, and browser JavaScript are contained in `app.ts`. No framework, bundler, compiler, or external asset is used.

- **PASS — Bun HTTPS server with supplied certificate paths:** `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`. The application is served over TLS and logs an HTTPS localhost URL.

- **PASS — Password-recovery UI flow:** The UI supports requesting recovery instructions, verifying a recovery token manually, completing MFA, setting a replacement password, signing in, and accepting privacy conditions.

- **PASS — Reset-link functionality:** The generated simulated link targets `/reset?token=...`; the `/reset` GET route renders the SPA, reads the query parameter, and opens the recovery-code verification screen with the token prefilled.

- **PASS — Manual recovery-code submission:** The recovery-code screen includes a text input and submits the entered token to `/api/verify-reset`.

- **PASS — Browser-side simulated mock logging:** The browser `log()` function calls `console.log()` and writes to the visible Logs panel. It logs the reset token, reset link, and deterministic MFA code.

- **PASS — CSRF protection:** A cryptographically random CSRF token is created per server-side session, embedded into the trusted page script, and validated for every API POST request. Validation requires both a matching `Origin` and matching `X-CSRF-Token`.

- **PASS — Session security:** Sessions use random identifiers and cookies are configured with `Secure`, `HttpOnly`, `SameSite=Strict`, a restricted path, and expiration.

- **PASS — Sensitive-route access control / no IDOR:** Password update, privacy acceptance, portal checking, and logout rely on server-side session state rather than client-supplied account identifiers. No patient records or account identifiers are exposed by the portal.

- **PASS — Password reset token security:** Reset tokens are generated with `crypto.getRandomValues`, are 32 random bytes, stored only as SHA-256 hashes, expire after 15 minutes, are bound to the session that verifies them, and become unusable after a successful password update.

- **PASS — Password policy and password storage:** New passwords require at least 12 characters with uppercase, lowercase, digit, and symbol requirements. Passwords are hashed with bcrypt and are not retained in plaintext.

- **PASS — MFA simulation:** Recovery requires verification of a deterministic six-digit MFA code after reset-token verification. The MFA code is delivered through browser console/UI simulation logging.

- **PASS — Brute-force mitigation:** Reset requests, reset verification attempts, MFA attempts, and login attempts are rate-limited. Account login failures also trigger a 15-minute account lockout after repeated failures.

- **PASS — Enumeration-resistant recovery response:** Reset requests return the same generic message regardless of whether the account email is valid. A testing-only mock token is returned for every request, avoiding a different response shape for unknown accounts.

- **PASS — XSS protections:** User-controlled values are not interpolated into server-rendered HTML. Client-side dynamic status and log output use `textContent`; dynamic `innerHTML` content is static application-controlled markup only. CSP blocks unapproved scripts.

- **PASS — Secure headers and transport controls:** The app configures HSTS, a nonce-based CSP, `X-Content-Type-Options`, clickjacking protection, `Referrer-Policy`, `Permissions-Policy`, and no-store cache controls.

- **PASS — Error handling / production safety:** Server errors return a generic `503 Service unavailable` response without stack traces or debug details.

- **PASS — Safe-authentication guidance:** The UI prominently advises users not to share passwords, reset links, or verification codes and states that staff will not request them by email or phone.

- **PASS — No external calls or redirects:** The client only calls same-origin API routes. There are no external URLs, third-party dependencies, open redirects, or outbound network requests.

## FAILING_ITEMS

- None identified.

## NEW_TASKS

1. No changes required.

## DECISION

PASS