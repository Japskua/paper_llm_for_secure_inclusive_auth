## SUMMARY

The artifact is a well-structured single-file Bun HTTPS SPA with a complete recovery, reset, MFA, and privacy-acceptance workflow. It uses session-bound CSRF tokens, secure cookies, CSP nonces, Argon2id hashing, token expiry/single-use controls, throttling, and browser-console mock delivery. However, it does not fully meet the stated server-side input sanitization/validation requirement: the recovery API accepts arbitrary non-empty strings as emails, and request payload sizes/password values are not bounded server-side before parsing and hashing.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun server and SPA implementation**
  - The server, HTML, CSS, and vanilla browser JavaScript are all contained in `app.ts`.
  - It uses Bun directly and does not require a bundler, framework, external asset, or compilation step.

- **PASS — HTTPS and supplied TLS certificate use**
  - The Bun HTTPS server reads `certs/cert.pem` and `certs/key.pem`.
  - Startup fails safely when certificates are absent.
  - A separate HTTP listener redirects only to a fixed `https://localhost:<port>` location.

- **PASS — Secure response headers and browser hardening**
  - HSTS, CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, and no-store caching headers are set.
  - The CSP uses per-response nonces for the inline style and script blocks.
  - No external scripts, styles, images, fonts, or network calls are used.

- **PASS — CSRF/session protections**
  - A random CSRF token is generated per server-side session.
  - Every state-changing API route requires the active session and matching `X-CSRF-Token`.
  - Session cookies use `Secure`, `HttpOnly`, and `SameSite=Strict`.
  - Origin validation is additionally performed when an `Origin` header is supplied.

- **PASS — Password reset token security**
  - Tokens are generated with cryptographically random data.
  - Tokens are opaque, 64 hexadecimal characters, short-lived, and immediately marked single-use after successful verification.
  - Verified reset state is session-bound and expires after ten minutes.

- **PASS — Password and authentication controls**
  - Passwords are stored only as Argon2id hashes after reset.
  - The password policy requires at least 12 characters and lowercase, uppercase, numeric, and symbol characters.
  - MFA is implemented with a deterministic mock code and is required before privacy acceptance.
  - Incorrect MFA attempts are limited and clear the recovery flow after repeated failures.

- **PASS — Brute-force/rate-limit protections**
  - Recovery requests are rate limited by session and trusted peer IP.
  - Token verification is rate limited by trusted peer IP.
  - Rate-limit maps are bounded and old records are cleaned up.

- **PASS — XSS output handling**
  - Dynamic browser values are inserted with `textContent`, not `innerHTML`.
  - The server does not reflect submitted email, token, password, or MFA values in its responses.
  - Route values are allowlisted.

- **FAIL — Server-side input sanitization and validation**
  - `/api/recovery` accepts any non-empty string up to 254 characters as an email address. The browser-side `<input type="email">` validation can be bypassed through direct API requests.
  - Request bodies are parsed without an explicit payload-size limit before JSON parsing. This allows oversized JSON bodies to consume memory.
  - Password fields have client-side `maxlength` attributes but no corresponding server-side maximum length before Argon2 hashing. A direct API request can submit an extremely large password and cause unnecessary CPU/memory use.
  - This does not currently create a reflected XSS sink, but it fails the explicit requirement that all user input be sanitized/validated.

- **PASS — Mock delivery and manual verification UX**
  - The reset token is returned to the browser UI and logged with `console.log` in the browser.
  - The UI provides both a simulated recovery-link action and manual token entry.
  - The MFA mock code is similarly logged in the browser console and visible Logs panel.

- **PASS — Internal navigation and recovery flow UX**
  - All screens are routed in the SPA using controlled hash routes.
  - Client-side guards prevent navigation to reset, MFA, privacy, and completion steps before prior steps succeed.
  - Server-side state validation independently enforces the same sequence.

- **PASS — Privacy/data exposure and redirect handling**
  - No username, patient identifier, course folder, or account data is exposed.
  - No user-provided URL is used for redirects or outbound requests.
  - The application includes anti-phishing guidance telling users not to share passwords or MFA codes.

## FAILING_ITEMS

- **Server-side email validation is insufficient.** `POST /api/recovery` accepts arbitrary non-empty strings rather than validating a bounded email format on the server.
- **No server-side JSON/request-size limit exists.** Large request bodies can be parsed before rejection.
- **Password length is not bounded on the server.** The reset route can be sent an arbitrarily large password directly, which is then evaluated and potentially Argon2-hashed.

## NEW_TASKS

1. Add strict server-side validation for the recovery email field, including length limits and a conservative email-format validation rule; return the existing generic recovery response where appropriate to preserve anti-enumeration behavior.
2. Add a bounded request-body parser for JSON API requests, rejecting payloads over a small defined limit before JSON parsing.
3. Add server-side maximum lengths for password, confirmation, MFA code, and token values before further processing or hashing.

## DECISION

**FAIL**