## SUMMARY

The artifact is a well-structured single-file Bun application with a functional browser-based recovery flow, server-side phases, CSRF validation, per-session throttling, bcrypt password hashing, secure DOM rendering, and use of supplied TLS certificates when available. However, it does not fully meet the HTTPS-enforcement requirement because it deliberately starts an unsecured HTTP server when certificates are absent. It also relies solely on client cookie expiry without enforcing session expiry server-side, and generic error responses omit the normal security-header set.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no framework, bundler, compiler, or external assets.**  
  The server, HTML template, CSS, and vanilla browser JavaScript are all contained in `app.ts`. It is directly runnable by Bun and does not reference external resources.

- **PASS — Password-recovery user flow works end to end.**  
  The UI supports recovery request, manual recovery-token entry, MFA verification, strong-password creation, sign-in confirmation, privacy-condition acceptance, appointment confirmation, and a completion screen. Server-side phase checks prevent skipping the flow.

- **PASS — Simulated recovery delivery is logged in the browser and the token can be manually submitted.**  
  The `/api/recover` response contains `testToken`; browser JavaScript logs it with `console.log` and displays it in the Logs panel. The user can paste the token into the recovery-token form.

- **PASS — Recovery tokens are opaque, random, short-lived, session-bound, and single-use.**  
  Tokens are generated using `crypto.getRandomValues`, are 32 random bytes encoded as Base64URL, expire after ten minutes, are checked with timing-safe comparison, and are cleared after successful use.

- **PASS — Sensitive state transitions have server-side authorization checks.**  
  Privacy acceptance requires an authenticated session in the `privacy` phase. Appointment booking requires authentication, privacy acceptance, and the `appointment` phase. The browser cannot set these server-controlled properties itself.

- **PASS — CSRF protections are implemented for sensitive API requests.**  
  A random per-session CSRF value is created server-side, submitted in JSON request bodies, timing-safely validated, and combined with strict same-origin validation for POST requests.

- **PASS — XSS protections are substantially implemented.**  
  Browser-generated dynamic content uses `textContent`, `createElement`, `replaceChildren`, and `append`; it does not use `innerHTML` for user-controlled data. Server responses do not reflect account, password, token, or MFA inputs. CSP uses a per-response nonce.

- **PASS — Password strength and password storage requirements are implemented.**  
  Passwords require at least 12 characters, upper/lowercase letters, a number, and a symbol. Confirmation matching and basic common/repetitive-password rejection are included. Passwords are stored only as bcrypt hashes through `Bun.password.hash`.

- **PASS — Brute-force controls exist for recovery token, MFA, password-reset validation, and sign-in attempts.**  
  Each protected action is limited to five failures per session before a 60-second block is applied.

- **PASS — Secure browser headers are generally configured.**  
  The application configures CSP, HSTS, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and no-store caching headers on normal application/API responses.

- **PASS — Safe-authentication and anti-phishing guidance is present.**  
  The interface warns users not to provide passwords to support contacts or through email and instructs them to verify the local hospital address.

- **FAIL — HTTPS is not enforced in all runtime configurations.**  
  When `certs/cert.pem` and `certs/key.pem` are not present, the application starts a plaintext HTTP listener on port 3000:
  ```ts
  Bun.serve({ port: HTTPS_PORT, hostname: "localhost", fetch: handler });
  ```
  This directly conflicts with the requirement that HTTPS be enforced and that unsecured networks must not expose sessions. It is especially problematic because the session cookie is marked `Secure`; browsers will not send/store it over HTTP, so the fallback is also not a reliably functional recovery session.

- **FAIL — Server-side session lifetime is not enforced.**  
  The cookie has `Max-Age=1800`, but `RecoverySession` has no expiry timestamp and the server never invalidates old entries in `sessions`. A captured or manually replayed session cookie can remain accepted indefinitely while the process is running, even after the browser-side cookie expiry. This is not adequate server-side session control for a sensitive healthcare recovery flow.

- **FAIL — Generic 503 error responses omit the configured security headers.**  
  The catch block returns only:
  ```ts
  headers: { "cache-control": "no-store" }
  ```
  Therefore HSTS, CSP, clickjacking protection, content-type protection, referrer policy, and permissions policy are absent when an internal error occurs.

## FAILING_ITEMS

- The application intentionally permits insecure HTTP operation if TLS files are unavailable, contrary to the HTTPS-enforcement requirement.
- The insecure fallback is also operationally inconsistent with the `Secure` session cookie, meaning session persistence will fail or behave unpredictably over the fallback HTTP listener.
- Sessions expire only through a browser-managed cookie attribute; the server’s in-memory `sessions` map has no expiry validation or cleanup.
- The global error path returns a response without the standard security headers configured for normal responses.

## NEW_TASKS

1. Remove the plaintext HTTP fallback on port 3000. If `certs/cert.pem` or `certs/key.pem` is unavailable, fail startup with a clear server-console error rather than serving the portal over HTTP.

2. Retain the optional HTTP redirect listener only as a redirect to the fixed HTTPS origin, and ensure the primary application handler is available exclusively through the TLS-enabled Bun server.

3. Add a server-enforced expiry field, such as `expiresAt`, to `RecoverySession`; reject and delete sessions whose expiry has passed in `sessionFor`.

4. Refresh the server-side session expiry only after appropriate authenticated/sensitive progress, or use a fixed short maximum lifetime suitable for password recovery. Periodically delete expired entries from the `sessions` map.

5. Update the handler catch block to create and return the same security-header set used by normal responses, including HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and no-store caching.

## DECISION

**FAIL**