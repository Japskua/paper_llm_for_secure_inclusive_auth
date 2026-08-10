## SUMMARY

The artifact is a well-structured single-file Bun HTTPS application with a functional multi-step recovery UI, browser-side mock delivery logs, CSRF protections, CSP/security headers, token expiry/single-use handling, MFA simulation, password-strength validation, bcrypt hashing, and throttling. However, it does not securely model account ownership: any caller can request a reset using arbitrary contact text and ultimately change one process-global password hash. It also does not provide the login/privacy-acceptance completion flow described in the use case. These are material functional and authentication-security failures.

## FUNCTIONAL_CHECK

- **Single-file Bun server with inline HTML/CSS/client JS and no build tooling — PASS**
  - All application source is contained in `app.ts`.
  - Bun serves the HTML and `/app.js` directly, with no framework, bundler, compiler, external CDN, or network calls.
  - The only external files are the prescribed TLS certificate files.

- **HTTPS enforcement and prescribed certificate use — PASS**
  - Reads `certs/cert.pem` and `certs/key.pem`.
  - Serves the application through TLS on port `3443`.
  - HTTP port `3000` performs a fixed `308` redirect to `https://localhost:3443`.
  - The redirect is fixed to localhost and does not use an untrusted redirect target.

- **Clear, ADHD-conscious multi-step recovery UX — PASS**
  - Provides a visible five-step progress indicator, orientation messaging, clear step names, recovery-state restoration, no page-level timeout, help content, and activity feedback.
  - Client-side `localStorage` preserves device progress, while the server remains authoritative for access to later steps.
  - Users can request another recovery code and can resume an active recovery session.

- **Recovery code delivery simulation and manual code entry — PASS**
  - A random reset token is generated server-side.
  - The client logs the simulated recovery token to the browser console through `audit()` and displays it in the activity log for the test simulation.
  - The code can be submitted manually in the recovery-code form.
  - The simulated recovery-link button opens a fixed same-origin `/recovery?reset=...` URL, and that path verifies the token.

- **Reset-token security properties — PASS**
  - Reset tokens use `randomBytes(...).toString("base64url")`.
  - Tokens are 32 random bytes, short-lived for 15 minutes, replaced on resend, and invalidated after password reset.
  - The token is tied to the server session that created it, preventing cross-session token use.
  - Replaced tokens no longer work.

- **CSRF protection and state-changing route protection — PASS**
  - A random CSRF token is created per server session.
  - All state-changing API routes use `protectedRequest()` and require the `X-CSRF-Token` header.
  - The session cookie is `HttpOnly`, `Secure`, `SameSite=Strict`, and has a random opaque identifier.
  - No CORS headers permit cross-origin credentialed requests.

- **XSS and client-side injection protections — PASS**
  - Dynamic UI output uses `textContent`, not `innerHTML`.
  - The recovery-link value is encoded using `encodeURIComponent`.
  - The CSP restricts scripts to same-origin `/app.js`; there are no inline JavaScript handlers or untrusted scripts.
  - User-provided contact details and passwords are not rendered back into HTML.

- **Security headers and anti-clickjacking/cache controls — PASS**
  - Includes HSTS, CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, and no-store cache controls.
  - The `no-referrer` policy is especially appropriate because reset tokens can appear in the recovery URL query string.

- **Password policy and password hashing — PASS**
  - Enforces at least 12 characters, upper/lowercase letters, a number, a symbol, and no whitespace.
  - Passwords are hashed with Bun’s bcrypt implementation before storage.
  - Passwords are not logged or stored in plaintext.

- **Brute-force mitigation — PASS**
  - Reset-token verification, MFA verification, and login attempts are rate-limited per session.
  - Additional cross-session/global throttling exists to reduce bypass through newly created sessions.
  - Failed attempts result in temporary lockout behavior.

- **MFA implementation — PASS**
  - The flow requires a second security-code step before allowing password change.
  - The deterministic MFA mock value is delivered to the browser activity log/console for the test scenario.
  - MFA verification is protected by CSRF, recovery-state checks, and throttling.

- **Password reset prevents unauthorized access — FAIL**
  - `/api/recovery/request` accepts any arbitrary string with length 3–254 as a “contact” and always creates a reset record.
  - There is no account lookup, account ownership verification, recipient binding, or proof that the requester controls the supplied email/phone.
  - A successful reset modifies the single global `storedPasswordHash`, not a password belonging to a validated account.
  - Therefore, any visitor who opens the application can complete the recovery flow and overwrite the shared password hash. This is an authorization failure, not merely a harmless mock.

- **Sensitive data and account isolation / IDOR resistance — FAIL**
  - The implementation uses one global credential variable: `let storedPasswordHash = "";`.
  - There is no account-scoped identity model, no authenticated user principal, and no binding between a recovery record and the credential being changed.
  - Although no usernames are exposed, the absence of account isolation means the password change operation is not safely authorized for a particular account.

- **End-to-end login and privacy-condition completion from the use case — FAIL**
  - A `/api/login` endpoint exists, but there is no login page, login form, authenticated portal state, or client-side route that uses it.
  - The completion screen tells the user they can return to a hospital sign-in page and accept privacy conditions, but no such internal page, route, link, or privacy-acceptance action exists.
  - This leaves the specified use case incomplete after password recovery.

- **Code validity / direct browser operation — PASS**
  - The TypeScript/JavaScript structure is syntactically coherent for Bun 1.3.0.
  - The referenced DOM element IDs exist for the client handlers.
  - The routes referenced by the browser client are implemented by the Bun server.
  - The TLS server setup, response creation, and Bun password API usage are consistent with direct Bun execution.

## FAILING_ITEMS

- **Unauthorized password reset is possible**
  - Any browser session can submit an arbitrary contact value to `/api/recovery/request`, receive a valid reset token, complete MFA using the deterministic code, and set a new password.
  - There is no verification that the requester controls the stated recovery contact or owns the account being reset.

- **The changed password is process-global instead of account-scoped**
  - `storedPasswordHash` is shared across all sessions and is not attached to an authenticated account.
  - One user’s recovery operation can overwrite the only password value used by the entire application.

- **No actual login-to-privacy completion flow exists**
  - The API includes a login endpoint, but the UI does not expose login.
  - There is no authenticated account screen or privacy-conditions acceptance state after recovery.
  - The completion screen references functionality that is not implemented as an internal route or link.

## NEW_TASKS

1. **Replace the global password state with an account-scoped mock account model.**
   - Store password hashes by an internal account key rather than in `storedPasswordHash`.
   - Keep account identifiers server-side and do not return usernames, account IDs, folders, or patient data to the browser.

2. **Bind each password-reset record to a validated account and authorized recovery channel.**
   - Validate the supplied recovery contact against the mock account’s registered recovery channel without revealing whether an account exists.
   - Associate the generated reset record with that account internally.
   - Ensure `/api/password/change` can change only the password hash for the account bound to the verified reset record.

3. **Preserve the required browser-visible mock delivery without making it a production-style authorization bypass.**
   - Make the browser-returned token explicitly limited to the test/demo recovery account and simulation mode.
   - Ensure arbitrary contact text cannot be used to obtain a reset capability for a shared or real account.
   - Continue logging the test token in the browser console as required.

4. **Implement the missing login and privacy-acceptance completion flow.**
   - Add a same-origin login route and accessible login form using the account-scoped credential model.
   - Establish a server-side authenticated session after successful login.
   - Add an authenticated privacy-conditions screen and a CSRF-protected acceptance action.
   - Link the recovery completion screen to the login route using a fixed internal path.

## DECISION

**FAIL**