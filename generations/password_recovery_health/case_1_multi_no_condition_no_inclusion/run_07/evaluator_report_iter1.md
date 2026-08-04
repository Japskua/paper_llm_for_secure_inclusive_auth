## SUMMARY

The artifact is a functional single-file Bun password-recovery SPA with a working simulated reset, MFA verification, password policy, session-bound reset grant, CSRF checks, rate limiting, Argon2id password hashing, and browser-console delivery logs. However, it does not fully meet the security requirements because HTTPS is optional rather than enforced, server-side sessions do not expire, and the CSP nonce is reused globally rather than generated per HTML response. These are material security-configuration and session-security defects.

## FUNCTIONAL_CHECK

- **Single `app.ts` artifact containing Bun server, HTML, CSS, and vanilla client JavaScript: PASS**
  - The supplied application is fully contained in one TypeScript file. It uses `Bun.serve`, returns an HTML template, and embeds CSS and browser-side JavaScript without frameworks, bundlers, external assets, or build tooling.

- **Bun TLS certificate usage: PARTIAL / FAIL**
  - The code correctly checks for and configures `certs/cert.pem` and `certs/key.pem` through `serverOptions.tls`.
  - However, it deliberately starts an unsecured HTTP server if certificates are absent. The requirements state that HTTPS must be enforced. A development HTTP fallback does not satisfy that requirement.

- **Password recovery request flow: PASS**
  - The recovery form validates an email address, makes a same-origin JSON request, creates a cryptographically random reset token, stores only its SHA-256 hash, assigns a 10-minute expiration, and returns a generic account-enumeration-resistant response.
  - The simulated token and MFA code are returned to the browser and logged through browser-side `console.log`, as required for testing.

- **Verification-link and manual-code flow: PASS**
  - The generated local hash route pre-fills the reset code in the verification screen.
  - The code can also be manually pasted into the recovery-code field.
  - Routing among `#recover`, `#verify`, `#new-password`, and `#portal` functions through `hashchange` handling.

- **MFA / additional verification step: PASS for the specified mock flow**
  - A recovery token and a six-digit MFA code are both required before a password reset grant is issued.
  - The MFA code is deterministic for testability and logged in the browser. This is acceptable for the stated mock/demo mechanism, although it is not suitable as production MFA.

- **Reset-token security: PASS**
  - Tokens are generated with `crypto.getRandomValues`, are sufficiently long, are stored hashed, expire after 10 minutes, and are invalidated after successful verification.
  - The password-setting action requires a short-lived, session-bound recovery grant.

- **Password policy and password storage: PASS**
  - Passwords require a minimum of 14 characters and uppercase, lowercase, numeric, and symbol characters.
  - Passwords are hashed with Bun Argon2id (`Bun.password.hash`) and are not intentionally stored in plaintext.

- **Brute-force mitigation: PASS**
  - Sensitive POST actions are rate limited to five attempts per minute per session.
  - The rate-limit logic is applied before reset, verification, password update, and privacy-condition acceptance actions.

- **CSRF protection and sensitive-request authorization: PARTIAL / FAIL**
  - Each newly created session receives a random CSRF token.
  - Sensitive requests require both an `Origin` header matching the local server origin and a matching CSRF token in both the request header and JSON body.
  - The session cookie is `HttpOnly`, `SameSite=Strict`, and marked `Secure` when TLS is enabled.
  - However, session expiration is only expressed in the browser cookie. The server-side `sessions` map never expires or removes sessions. A previously obtained session ID could still be accepted by the server after the cookie’s nominal 30-minute lifetime if manually replayed.

- **Access control / IDOR prevention: PASS**
  - Sensitive actions are tied to the current session and do not accept user-controlled account or patient identifiers.
  - The privacy acceptance endpoint checks `session.authenticated`.
  - The application does not expose usernames, patient records, course folders, or similar private identifiers.

- **XSS/input-injection controls: PARTIAL / FAIL**
  - User-provided values are not interpolated into HTML. The client uses `textContent` for dynamic messages and values are validated server-side.
  - The client’s `innerHTML` assignments contain only developer-controlled static templates.
  - CSP is configured with a script/style nonce and restrictive directives.
  - However, `cspNonce` is created once at server startup and reused for every HTML response. CSP nonces should be generated uniquely per document response; reusing one makes the nonce observable and reusable across page loads, weakening the intended CSP protection.

- **Secure response headers: PARTIAL / FAIL**
  - The app supplies CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, and `Cache-Control: no-store`.
  - HSTS is added only when certificates are present.
  - Because the server can run via HTTP without TLS and without HSTS, HTTPS/HSTS are not enforced in all supported execution modes.

- **No external calls, SSRF, or open redirects: PASS**
  - Client requests are limited to local relative API paths.
  - Hash-route parsing only reads a local recovery-code parameter.
  - There are no outgoing server requests, user-provided destination URLs, redirects, or external resources.

- **Social-engineering/phishing safety guidance: PASS**
  - Every flow screen displays guidance telling users that hospital staff will not request passwords or recovery codes through email or telephone.

- **Production-safe error handling: PASS**
  - The server returns controlled JSON messages and does not expose stack traces, directory listings, internal account data, or debugging details to the browser.

## FAILING_ITEMS

- **HTTPS is not enforced.**
  - When `certs/cert.pem` and `certs/key.pem` are unavailable, the app intentionally starts an HTTP server on port 3000.
  - This conflicts with the explicit requirement that HTTPS be enforced and that insecure networks must not expose sessions.

- **Server-side sessions have no expiration or cleanup.**
  - `Session.createdAt` is recorded but never checked.
  - `sessions` is an unbounded in-memory map, and an expired browser cookie does not invalidate its corresponding server-side session.
  - A stolen or manually replayed session cookie could remain accepted indefinitely while the process remains running.

- **The CSP nonce is global and reused across all responses.**
  - `cspNonce` is generated at module initialization rather than per HTML response.
  - Reused CSP nonces weaken the CSP defense model and do not provide per-document nonce protection.

## NEW_TASKS

1. Remove the HTTP fallback and require `certs/cert.pem` and `certs/key.pem` before starting the Bun server; always configure TLS and always set `Secure` cookies and HSTS.

2. Add a server-side session lifetime, validate it in `getSession` and/or before sensitive actions, delete expired sessions, and periodically clean stale entries from the `sessions` map.

3. Generate a fresh CSP nonce for every HTML response, pass that nonce to both `page(...)` and `baseHeaders(...)`, and ensure the response-specific nonce is used for the inline stylesheet and script.

## DECISION

**FAIL**