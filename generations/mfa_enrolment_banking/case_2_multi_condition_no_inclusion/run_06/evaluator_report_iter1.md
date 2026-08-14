## SUMMARY

The artifact is structurally compliant as a single `app.ts` Bun/TLS server with inline HTML, CSS, and vanilla JavaScript. It includes many strong security controls, including server-side sessions, CSRF tokens, secure cookies, security headers, encrypted OTP seeds, hashed recovery codes, rate limiting, and generic errors. However, it has critical functional and security defects: browser POST requests from the configured HTTPS server will be rejected due to an incorrect trusted-origin allow-list; most generated authenticator secrets cannot pass validation; and the claimed authenticator-app setup is not a standards-compatible TOTP implementation. It also treats any syntactically valid credentials as the account owner and permits navigation to an “MFA active” dashboard before MFA is active.

## FUNCTIONAL_CHECK

- **FAIL — Single-file Bun application with no frameworks, bundlers, compilers, or external assets**
  - The complete app is contained in `app.ts`, uses `Bun.serve`, and embeds HTML, CSS, and browser JavaScript. No external assets or build tooling are used.
  - However, this criterion cannot be fully accepted because the delivered application is functionally broken for browser POST interactions due to origin validation.

- **PASS — HTTPS/TLS is configured using the required mkcert certificate paths**
  - `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`.
  - The server only listens through the TLS configuration.

- **FAIL — The MFA enrolment UI and its internal flow function correctly**
  - Same-origin browser POST requests will normally send an `Origin` such as `https://localhost:3000`.
  - `TRUSTED_ORIGINS` only contains `https://localhost`, `https://127.0.0.1`, and `https://[::1]`, without port `3000`.
  - The handler rejects any supplied origin not in that set with HTTP 403. Consequently, login and all subsequent POST API calls fail when using the configured server.

- **FAIL — Authenticator provisioning and verification work using deterministic simulated values**
  - The server generates the provisioning secret from `alphabet`, which includes `8` and `9`.
  - `validSecret()` only permits `[A-Z2-7]{32}`.
  - A generated secret containing `8` or `9` is shown to the user but rejected by `/api/verify-authenticator`. This occurs for the majority of generated secrets.
  - Therefore the simulated verification flow does not reliably work.

- **FAIL — Manual authenticator setup supports an actual time-based OTP authenticator**
  - The UI tells the user to copy the secret into an authenticator app.
  - The server’s `otpFor()` uses a custom HMAC construction over the decimal string of the time step rather than RFC 6238 TOTP formatting, including an 8-byte counter and dynamic truncation.
  - Standard authenticator applications will not generate the server’s expected code from the displayed secret. The manual setup instructions are therefore inaccurate and the real authenticator-app flow does not work.

- **FAIL — Only the authenticated account owner can access or modify MFA settings**
  - MFA endpoints correctly derive the user only from the server-side session and reject client-supplied `userId`, `accountId`, and `ownerId`.
  - However, `/api/login` accepts any syntactically valid email and any password of at least eight characters, then creates a session for `ACCOUNT_OWNER_ID`.
  - This means arbitrary credentials can obtain an authenticated session for Marcus’s account in the demo, violating the requirement that only the authenticated account owner may access the account.

- **PASS — CSRF protection is applied to authenticated state-changing MFA operations**
  - Authenticated POST requests require a matching `X-CSRF-Token`.
  - Session cookies are `SameSite=Strict`.
  - MFA enabling, identity updates, backup-code regeneration, recovery-code consumption, and logout are protected by the CSRF check.

- **PASS — Session security controls are present**
  - Session IDs are generated with cryptographic randomness.
  - Existing sessions are deleted and a new session is issued on login.
  - Cookies include `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - Idle and absolute session expiration are implemented.
  - Logout invalidates the server session and expires the cookie.

- **PASS — Security headers and restricted CORS are implemented**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, cache prevention, referrer policy, and permissions policy are set.
  - CORS is intended to be restricted to trusted origins.
  - The configured CORS/origin list is functionally incorrect for port 3000, but it remains restrictive rather than permissive.

- **PASS — Sensitive values are not written to server logs, URLs, browser storage, or non-HttpOnly cookies**
  - No `localStorage` or `sessionStorage` is used.
  - Session IDs remain in HttpOnly cookies.
  - Secrets, OTPs, and recovery codes are deliberately shown and logged only in the browser console/UI as required for the academic mock.
  - No server-side sensitive-value logging is present.

- **PASS — OTP seeds and recovery codes use cryptographically secure generation and protected server storage**
  - OTP seeds are generated with `crypto.getRandomValues` and encrypted with AES-GCM while stored in process memory.
  - Recovery codes are generated with `crypto.getRandomValues` and only their peppered SHA-256 values are retained server-side.
  - Recovery-code plaintext is returned only at generation time for the required test UI.

- **PASS — Verification attempts are time-bound, single-use on success, and rate-limited**
  - Authenticator provisioning expires after 15 minutes.
  - OTP validation uses 30-second time steps and records used time steps after a successful verification.
  - Recovery codes are deleted after successful use.
  - Both authenticator and recovery verification flows have failure counters and lockouts.

- **FAIL — UI state accurately reflects MFA status and prevents invalid navigation**
  - A logged-in user can directly navigate to `#/dashboard` before completing MFA.
  - `renderDashboard()` always displays “Authenticator MFA is active,” even if `state.me.mfaActive` is false.
  - This creates a misleading security status and exposes controls that will subsequently fail server-side.

- **PASS — Input validation, generic errors, output safety, and redirect controls are present**
  - Server-side validation exists for email, phone, OTP, setup secret, and recovery code inputs.
  - Client-controlled user/account identifiers are rejected.
  - Errors are generic.
  - The redirect target is restricted through `safeInternalPath`.
  - User-provided fields are assigned through DOM properties rather than interpolated into HTML.

## FAILING_ITEMS

- Same-origin POST requests from `https://localhost:3000`, `https://127.0.0.1:3000`, or `https://[::1]:3000` are rejected because `TRUSTED_ORIGINS` excludes the port used by `Bun.serve`.
- Provisioning secrets can contain `8` or `9`, but the verifier rejects these values through `validSecret()`, making authenticator verification fail for most generated secrets.
- The custom `otpFor()` algorithm is not RFC 6238-compatible TOTP, despite UI instructions telling users to enter the secret into an authenticator application.
- Login creates a valid session for `ACCOUNT_OWNER_ID` for any valid-format email and any password of sufficient length, so account ownership is not actually authenticated.
- The client permits routing to the dashboard before `mfaActive` is true and incorrectly claims MFA is active.

## NEW_TASKS

1. Update trusted-origin validation so the actual TLS serving origins are allowed, including `https://localhost:3000`, `https://127.0.0.1:3000`, and `https://[::1]:3000`; retain strict rejection of untrusted origins.

2. Separate the provisioning-secret alphabet from the recovery-code alphabet and ensure generated provisioning secrets exactly match server validation, preferably using RFC 4648 Base32 characters `A-Z` and `2-7`.

3. Replace the custom OTP calculation with RFC 6238-compatible TOTP generation and verification using Base32-decoded secret bytes, an 8-byte time counter, HMAC dynamic truncation, and the documented 30-second period; retain deterministic browser console mock delivery of the currently valid OTP.

4. Replace the “any valid credentials” login behavior with deterministic mock credential validation for the demo account. Return the same generic login failure response for invalid email/password combinations and only create a session for valid mock credentials.

5. Add client-side route guards based on `state.me.identityVerified` and `state.me.mfaActive`, and render the dashboard’s MFA-active message only when MFA is actually active. Redirect users without active MFA to the appropriate remaining enrolment step.

## DECISION

FAIL