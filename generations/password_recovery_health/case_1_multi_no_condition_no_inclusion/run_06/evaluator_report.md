## SUMMARY

The artifact is a well-structured single-file Bun HTTPS application with a functional recovery flow, server-side sessions, CSRF validation, short-lived single-use reset tokens, bcrypt password hashing, MFA simulation, security headers, and browser-console mock delivery logs. Most functional and security requirements are met. However, it does not meet the explicit requirement that no inline scripts be allowed: the entire client application is embedded in an inline `<script>` block. This is mitigated by a CSP nonce but still violates the stated requirement. The unbounded creation of server sessions on unauthenticated `GET /` requests is also an availability/memory-retention concern.

## FUNCTIONAL_CHECK

- **Single file (`app.ts`) containing Bun server, HTML, CSS, and vanilla JavaScript: PASS**
  - The provided artifact is entirely contained in `app.ts`, with no framework, bundler, compiler, or external client asset dependency.

- **Bun HTTPS server uses supplied TLS certificate paths: PASS**
  - The application checks for `certs/cert.pem` and `certs/key.pem`, fails closed if either is missing, and configures `Bun.serve` with TLS.
  - A separate HTTP listener redirects to the fixed `https://localhost:<HTTPS_PORT>` URL.

- **HTTPS enforcement and secure headers: PASS**
  - HTTPS is used for the portal, HTTP redirects to HTTPS, and responses include HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, permissions policy, COOP, CORP, and no-store cache controls.

- **CSRF protection for sensitive state-changing requests: PASS**
  - Each server session has a random CSRF token.
  - All POST API routes require a valid session and matching `X-CSRF-Token`.
  - Session cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`.

- **Session authorization / access-control enforcement: PASS**
  - Password replacement requires a verified reset token.
  - MFA requires a completed password replacement.
  - Privacy-condition acceptance requires MFA completion.
  - Reset-link sessions are restricted until the reset code is verified.

- **Secure reset token behavior: PASS**
  - Reset tokens are generated with cryptographic randomness, are URL-safe, expire after ten minutes, are server-side tracked, and are consumed after successful verification.
  - The reset token is not consumed by a GET request; verification still requires a CSRF-protected POST.

- **Manual recovery-code entry and recovery-link flow: PASS**
  - The recovery link contains a token query parameter and opens the verification screen.
  - Users can also enter the recovery code manually.
  - The code is shown only in the local browser Logs panel and browser console as required for testing.

- **Recovery, password reset, MFA, privacy acceptance, and completion UI flow: PASS**
  - The client-side UI transitions correctly through all required stages.
  - The API checks server-side state at every transition rather than trusting client-side screen state.

- **Rate limiting / brute-force mitigation: PASS**
  - Recovery, reset-token verification, MFA, and login routes have client-level throttling based on direct server peer metadata.
  - Session-level limits additionally constrain recovery, verification, MFA, and login attempts.
  - Forwarded headers are not trusted for client identification.

- **Password policy and password hashing: PASS**
  - Passwords must be 12–128 characters, contain upper/lowercase characters, a digit, and a symbol, and contain no spaces.
  - Passwords are hashed using Bun bcrypt with cost 10 and are not returned in responses.

- **MFA implementation: PASS**
  - A simulated six-digit MFA code is required after password replacement.
  - The deterministic code is returned only for the local demonstration and logged in the browser.

- **XSS prevention and safe rendering of user-controlled values: PASS**
  - The UI uses DOM APIs and `textContent`; it does not interpolate user-provided values into HTML.
  - Inputs are validated server-side and client-side.
  - API messages are controlled by server code rather than reflected user input.
  - No external URLs or open redirects are accepted from user input.

- **No exposure of patient identifiers, usernames, course data, or private account data: PASS**
  - The UI and API do not disclose an account’s existence, username, patient information, or other private identifiers.
  - Recovery responses use generic language.

- **Safe-authentication / anti-phishing guidance: PASS**
  - Every recovery screen includes guidance telling users not to share passwords or security codes and to verify the `https://localhost` address.

- **No external network calls: PASS**
  - The client only calls same-origin API endpoints. Delivery is simulated through browser `console.log` and the on-page Logs panel.

- **No inline or untrusted scripts: FAIL**
  - The HTML contains a large inline `<script nonce="...">` block containing the full client application.
  - A CSP nonce authorizes that script, but it remains an inline script and therefore does not satisfy the explicit requirement: “No inline or untrusted scripts are allowed.”

- **Production-safe error handling: PASS**
  - Errors are caught at the request boundary and return a generic response without stack traces or debug details.

- **Bounded server-side state / resistance to unauthenticated memory exhaustion: FAIL**
  - Every unauthenticated `GET /` request creates a session, and the `sessions` map has no maximum size or GET-level throttling.
  - An attacker can repeatedly request the root page and retain many sessions for up to 30 minutes, causing unnecessary server memory growth.

## FAILING_ITEMS

- The client application is implemented as an inline `<script>` element. Although it has a CSP nonce, this directly conflicts with the requirement that inline scripts not be allowed.
- Unauthenticated `GET /` requests can create unlimited sessions because `sessions` has no maximum size and root-page requests are not rate limited. This permits avoidable memory exhaustion through repeated page loads.
- The client script applies `label.style.margin = "0"` at runtime. With the current CSP, inline style attributes are not permitted by `style-src 'nonce-...'`; this cosmetic declaration may be blocked and produce a CSP violation. The style should be represented by a CSS class instead.

## NEW_TASKS

1. Move the browser JavaScript from the inline `<script>` block into a same-file Bun-served endpoint such as `GET /client.js`; serve it from `app.ts` with `Content-Type: application/javascript` and load it using `<script src="/client.js" defer></script>`.
2. Pass the per-session CSRF token to the external client script safely, for example through a server-rendered `<meta name="csrf-token" content="...">` element that the external script reads. Update CSP to allow only same-origin scripts, e.g. `script-src 'self'`, without a nonce-based inline-script exception.
3. Add a bounded session policy: impose a maximum `sessions` map size and/or rate-limit unauthenticated `GET /` session creation by direct client IP. Return a generic retry response rather than allocating a new session when the cap is reached.
4. Replace `label.style.margin = "0"` with a predefined CSS class, such as `.check-row label { margin: 0; }`, so no inline style attribute is attempted under the CSP.

## DECISION

**FAIL**