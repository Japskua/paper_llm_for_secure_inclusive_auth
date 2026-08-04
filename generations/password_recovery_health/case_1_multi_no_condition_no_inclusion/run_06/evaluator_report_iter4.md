## SUMMARY

The artifact is a single `app.ts` Bun HTTPS application with an inline vanilla HTML/CSS/JS SPA. It provides a complete simulated recovery flow, including manual/link token verification, password policy and bcrypt hashing, MFA verification, privacy acceptance, CSRF protection, security headers, TLS enforcement, and browser-console delivery logs. However, its rate limiting is keyed solely to newly creatable session IDs, so automated attackers can bypass recovery, MFA, and login throttles simply by starting new sessions. This does not meet the brute-force mitigation requirement robustly.

## FUNCTIONAL_CHECK

- **Single-file Bun server with inline HTML, CSS, and vanilla JavaScript: PASS**  
  All server logic and the rendered SPA are contained in `app.ts`. It uses `Bun.serve` directly and does not rely on frameworks, bundlers, compilation steps, or external assets.

- **HTTPS enforcement and supplied certificate usage: PASS**  
  The server checks for `certs/cert.pem` and `certs/key.pem`, fails closed if unavailable, starts a TLS server with those files, and redirects HTTP traffic to a fixed `https://localhost:<port>` URL.

- **Secure headers, HSTS, CSP, and no-store caching: PASS**  
  Responses include HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, permissions policy, COOP/CORP, and no-store cache control. The HTML uses a per-response CSP nonce for its trusted style and script blocks.

- **CSRF protection on state-changing actions: PASS**  
  Every recovery, token-verification, password-update, MFA, privacy-acceptance, and login API route requires a session and validates a server-generated per-session CSRF token using timing-safe comparison.

- **Session cookie protections: PASS**  
  The recovery session cookie is `HttpOnly`, `Secure`, `SameSite=Strict`, path-scoped, opaque, random, and has a limited lifetime.

- **Password reset tokens are random, short-lived, and single-use: PASS**  
  Reset tokens are generated with cryptographic randomness, expire after ten minutes, are validated server-side, become unusable after verification, and are removed from the token store.

- **Recovery link and manual recovery-code submission work: PASS**  
  The UI logs a simulated recovery token and recovery URL to the browser console and visible Logs panel. A token in the URL opens the verification page, while users may also manually paste or enter the token.

- **Password security and storage: PASS**  
  The password policy requires at least 12 characters with uppercase, lowercase, numeric, and symbolic characters and prohibits spaces. Passwords are hashed using Bun bcrypt before being stored in the in-memory session state; plaintext passwords are not persisted.

- **MFA flow works in the simulated environment: PASS**  
  After a password update, the application displays/logs a deterministic simulated MFA code and requires it before privacy acceptance. The code is suitable for the explicitly simulated test flow.

- **Privacy acceptance requires completed recovery and MFA: PASS**  
  The privacy endpoint requires a CSRF-protected session, a completed password reset, a completed MFA step, and an explicit `accepted: true` request.

- **XSS and unsafe DOM insertion prevention: PASS**  
  User-controlled values are not interpolated into HTML. Client-side dynamic content is created with DOM APIs and `textContent`, and server-side input validation restricts fields. The CSP prevents execution of untrusted scripts.

- **No exposure of patient identifiers or account data: PASS**  
  The UI does not render usernames, patient data, folders, or other private records. Recovery responses use account-enumeration-resistant generic wording.

- **Brute-force / automated-attempt mitigation: FAIL**  
  Rate-limit keys are based on `session.id`, for example `recovery:${session.id}`, `verify:${session.id}`, `mfa:${session.id}`, and `login:${session.id}`. An attacker can obtain a new anonymous session by requesting `/`, thereby resetting the effective rate limit. This means the system does not meaningfully throttle automated attempts across sessions.

- **No open redirects or external network calls: PASS**  
  The HTTP redirect always targets a fixed localhost HTTPS origin and only preserves the local path/query. Client-side requests are same-origin API requests only.

- **Non-debug error behavior: PASS**  
  Exceptions are caught by `safeHandle`, and generic error responses do not disclose stack traces or internal implementation details.

## FAILING_ITEMS

- **Rate limiting can be bypassed by session creation.**  
  The application creates anonymous sessions on `GET /`, while rate-limit keys are scoped only to `session.id`. A bot can make a new request/session whenever a limit is reached, bypassing recovery-request, MFA, and login throttles.

- **MFA retry limiting is not durable across recovery sessions.**  
  The MFA retry limit is also session-scoped. Since new recovery sessions can be created without a persistent account- or client-bound throttle, repeated automated MFA attempts are not effectively blocked at the system level.

## NEW_TASKS

1. Add a server-side client-level rate-limit key that cannot be reset by simply creating a new session, such as a carefully normalized client IP address derived only from the direct connection metadata; do not trust arbitrary forwarding headers unless deployed behind a trusted proxy configuration.

2. Apply the client-level rate limiter to `/api/recovery`, `/api/verify-token`, `/api/mfa`, and `/api/login` in addition to the existing per-session and per-token limits.

3. Add a bounded cleanup routine for the new client-level rate-limit records so expired entries are removed without retaining client metadata beyond the throttle window.

## DECISION

**FAIL**