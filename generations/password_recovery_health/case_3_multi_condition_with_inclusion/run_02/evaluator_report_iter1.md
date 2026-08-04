## SUMMARY

The artifact is a well-structured single-file Bun HTTPS SPA with a clear, low-distraction recovery flow, CSRF protections, password hashing, MFA simulation, and accessible feedback. However, it must not be accepted because password-code verification is likely nonfunctional due to an invalid `crypto.timingSafeEqual` call, and several security requirements are incomplete: rate limiting is session-scoped and bypassable, server sessions do not expire server-side, mock logging occurs on the server despite the browser-only requirement, and security headers are not consistently applied.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no frameworks, build tools, external assets, or network calls**
  - All server logic, HTML, CSS, and browser JavaScript are in `app.ts`.
  - It uses `Bun.serve()` directly and does not require a bundler or compiler.
  - The UI does not load external assets or make external requests.

- **PASS — TLS is configured with the required local certificates**
  - The server uses `certs/cert.pem` and `certs/key.pem` through `tls: { cert: CERT, key: KEY }`.

- **FAIL — Password reset verification works through both a link and manual code entry**
  - The UI correctly provides both a simulated recovery link and a manual code field.
  - However, `verifyReset()` calls `crypto.timingSafeEqual(...)`. `globalThis.crypto` is the Web Crypto API and does not provide Node’s `timingSafeEqual` method. When a submitted token has the correct length, this can throw a runtime error and return the generic 500 response.
  - This prevents the recovery-code step, and therefore the full password-reset journey, from reliably functioning.

- **PASS — Internal recovery link navigation functions**
  - The generated `deliveryPath` uses `/?reset=<token>`.
  - Client routing reads `reset`, stores it in `recoveryToken`, switches to the verification panel, and also supports `#verify`.

- **PASS — Password policy and secure password storage**
  - Passwords require at least 12 characters with uppercase, lowercase, numeric, and symbolic characters.
  - Passwords are stored with `Bun.password.hash(..., { algorithm: "argon2id" })`.
  - Plaintext passwords are not persisted in account storage.

- **PASS — MFA is implemented and verification is session-bound**
  - A six-digit MFA code is generated after successful password verification.
  - MFA codes expire after ten minutes and use a per-session failure counter and lockout.

- **FAIL — Brute-force protections adequately throttle automated login attacks**
  - Login, MFA, and reset-token failures are throttled only inside the current session.
  - An attacker can obtain a new session simply by dropping the cookie or opening a new browser context, then continue guessing passwords against the same account.
  - Login throttling must be tied to the account identifier/account key (and ideally a bounded IP-based control), not only the current session.

- **PASS — CSRF protection is present on sensitive requests**
  - Sessions receive random CSRF tokens.
  - Sensitive POST routes validate both `Origin` and `X-CSRF-Token`.
  - Cookies use `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, and the valid `__Host-` prefix format.

- **PASS — Sensitive appointment and privacy routes enforce authorization**
  - Privacy acceptance requires an authenticated session with completed MFA.
  - Appointment confirmation additionally requires accepted privacy conditions.
  - The client does not control authorization state; the server checks it.

- **FAIL — Server-side session lifetime is enforced**
  - The cookie has `Max-Age=28800`, but sessions in the `sessions` map have no expiration check or cleanup.
  - A previously issued session ID remains valid on the server indefinitely if manually replayed after browser cookie expiry.
  - Server-side session expiration must be enforced.

- **PARTIAL / FAIL — Security headers are comprehensively configured**
  - The HTML response receives HSTS, CSP, clickjacking protection, referrer policy, permissions policy, and cache-control headers.
  - JSON API responses and error responses do not consistently receive HSTS, CSP, frame protection, referrer policy, or permissions policy.
  - At minimum, HSTS and relevant security headers should be applied consistently to all HTTPS responses.

- **PASS — XSS protections and safe DOM rendering**
  - Dynamic UI values are inserted using `textContent`, not `innerHTML`.
  - Input validation restricts identifier and token formats.
  - The CSP uses a per-page nonce and denies default sources.
  - No user-controlled value is interpolated into server-rendered HTML.

- **FAIL — All mocks are logged in the browser only**
  - The requirements explicitly require mocks via `console.log` **in the browser**.
  - The server currently logs mock delivery, password replacement, MFA generation, privacy acceptance, and appointment confirmation with server-side `console.log(...)`.
  - Browser-side mock logging exists, but server-side mock logging violates the stated deliverable requirement.

- **FAIL — Recovery cannot be used to create arbitrary accounts**
  - `resetRequest()` creates a new account record whenever a submitted identifier does not already exist:
    - `account = { passwordHash: "", createdAt: now() };`
    - `accounts.set(accountKey, account);`
  - This makes the password-recovery process an account-provisioning endpoint. Anyone can submit an arbitrary identifier, reset its password, and create an account.
  - Recovery should issue a usable reset only for an existing mock account, while retaining a generic non-enumerating response for unknown identifiers.

- **PARTIAL / FAIL — ADHD-inclusive flow avoids unexpected page changes**
  - The process is otherwise clear, low-density, has visible progress, live feedback, help text, no countdown UI, and restoration via API state.
  - Successful actions automatically switch panels after 400–500 ms using `setTimeout(...)`.
  - This conflicts with the requirement to avoid unexpected page changes. The user should explicitly select a clearly labeled “Continue to next step” button, or focus should move predictably with an announced transition.

- **PARTIAL / FAIL — Private identifiers are not unnecessarily retained**
  - The identifier is saved to `localStorage` as `hospital-recovery-identifier`.
  - This persists an account reference beyond the stated browser-session recovery process and is unnecessary for authorization.
  - Use `sessionStorage` if local client-side restoration is needed, or avoid persistent client storage entirely.

## FAILING_ITEMS

- Recovery-code verification may fail at runtime because `crypto.timingSafeEqual` is not available on the Web Crypto global object.
- Account creation is incorrectly embedded in the recovery request flow, allowing arbitrary identifiers to become accounts.
- Login throttling is scoped only to a session and can be bypassed by starting a new session.
- Server-side sessions have no expiry validation or cleanup, despite the cookie having an eight-hour lifetime.
- Security headers, especially HSTS, are only applied to the main HTML response rather than consistently across API and error responses.
- Server-side `console.log` calls are used for mocks, contrary to the browser-only mock logging requirement.
- The UI automatically advances between panels after short timers, creating potentially unexpected page changes.
- The account identifier is stored persistently in `localStorage`.

## NEW_TASKS

1. Replace `crypto.timingSafeEqual(...)` with a valid Bun/Node implementation, such as importing `timingSafeEqual` from `node:crypto`, and ensure equal-length reset tokens can be verified without throwing.

2. Change recovery handling so it never creates accounts. Pre-provision deterministic mock account records server-side, return the same generic recovery response for all identifiers, and create a usable session reset token only when the submitted identifier maps to an existing account.

3. Implement account-level authentication throttling keyed by the hashed account identifier, including failure counts and lockout expiry that cannot be bypassed by creating a new session. Apply equivalent bounded issuance controls to recovery requests.

4. Add server-side session expiry metadata and reject/delete expired sessions in `getSession()` or a dedicated session-validation function. Periodically remove expired sessions.

5. Centralize response-header generation so all successful API, error, and 404 responses include appropriate HTTPS security headers, especially HSTS, `X-Content-Type-Options`, referrer policy, frame restrictions, and no-store caching.

6. Remove all server-side mock `console.log` calls. Return only test-safe mock values in API responses and log mock delivery/verification events exclusively through the existing browser `addLog()` / `console.log()` behavior.

7. Replace automatic `setTimeout(... choose(...))` panel transitions with explicit, visible “Continue” controls after successful steps, preserving clear progress and focus management.

8. Replace `localStorage` identifier persistence with `sessionStorage`, or remove client persistence and rely on server session state for recovery progress.

## DECISION

**FAIL**