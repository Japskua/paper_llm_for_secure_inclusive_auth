## SUMMARY

The artifact is a strong single-file Bun HTTPS MFA enrolment SPA with responsive mobile UI, accessible step-based flow, simulated OTP delivery, authenticator setup, QR/manual secret options, recovery codes, CSRF protection, secure session cookies, encrypted OTP secrets, hashed recovery codes, and verification lockouts. However, it does not fully meet the security requirements because login processing permits account enumeration through timing differences, and server-side email validation is incomplete. Therefore it cannot be accepted as fully compliant.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no build tools or external assets**
  - The complete server, HTML, CSS, client-side JavaScript, QR generation logic, and TLS configuration are contained in `app.ts`.
  - It uses `Bun.serve` directly and does not rely on frameworks, bundlers, compilers, CDNs, or external network calls.

- **PASS — HTTPS/TLS configuration and secure transport**
  - The Bun server is configured with `certs/cert.pem` and `certs/key.pem`.
  - HSTS is set with `max-age=31536000; includeSubDomains`.
  - The application only serves through the TLS-enabled Bun server.

- **PASS — Responsive, mobile-oriented, dyslexia-conscious UI**
  - The page uses a mobile viewport meta tag and constrained mobile layout.
  - Font sizing, line height, letter spacing, generous spacing, plain language, short instructions, icons, clear progress steps, and no moving content support the stated inclusivity goals.
  - Inputs use relevant browser features such as `autocomplete="username"`, `autocomplete="current-password"`, and `autocomplete="one-time-code"`.

- **PASS — Clear MFA enrolment flow**
  - The flow correctly supports sign-in, identity-code request/verification, authenticator provisioning, authenticator-code verification, recovery-code display/copy/print/regeneration, confirmation, and logout.
  - Primary actions are prominent and the current step is visually indicated.

- **PASS — Simulated OTP delivery and deterministic mock values**
  - The identity code is delivered through `/api/identity/request` and logged in the browser.
  - A deterministic mock TOTP is returned and logged in the browser for testing.
  - Recovery codes are returned to the UI and logged in the browser, as explicitly required for the simulation.

- **PASS — Manual authenticator setup and QR support**
  - The app provides a generated provisioning URI, QR code, revealable setup secret, copy-secret functionality, and copy-provisioning-link functionality.
  - A manual setup secret can be used if QR scanning is not available.

- **PASS — Recovery-code usability**
  - Recovery codes can be revealed, copied, printed/saved as PDF, regenerated, and confirmed.
  - Regeneration invalidates the old code verifiers on the server.

- **PASS — MFA endpoint authorization and IDOR resistance**
  - MFA account resolution is based on `Session.accountId`, not a client-supplied account identifier.
  - Protected endpoints use `sessionFor()` and derive the account from the authenticated session.
  - There is no exposed user ID parameter that can be manipulated to access another account’s MFA configuration.

- **PASS — CSRF protection for state-changing operations**
  - Login uses a dedicated login CSRF token plus a Strict cookie and same-origin validation.
  - Authenticated state-changing API calls require `X-CSRF-Token`, same-origin validation, and a valid server-side session CSRF token.
  - Session cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`.

- **PASS — Security headers and clickjacking protection**
  - CSP includes nonce-based script and style restrictions.
  - HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, referrer policy, permissions policy, and no-store cache control are set.
  - The CSP limits connections to same origin.

- **PASS — Secure storage of MFA material**
  - The authenticator secret is encrypted server-side using AES-256-GCM.
  - Recovery codes are generated with `randomBytes` and stored as salted `scrypt` verifiers.
  - MFA secrets, recovery codes, and session IDs are not stored in `localStorage`, `sessionStorage`, or client-readable cookies.

- **PASS — OTP/recovery-code lifecycle and lockout controls**
  - Identity codes are time-bound and single-use.
  - TOTP counters are recorded to prevent reuse.
  - Recovery codes are removed after successful use.
  - Identity, authenticator, and recovery verification attempts have attempt limits and ten-minute lockouts.

- **PASS — Session lifecycle controls**
  - Sessions are created with cryptographically secure random IDs.
  - A new session is generated on successful authentication, mitigating session fixation.
  - Idle and absolute session expiry are enforced.
  - Logout invalidates the server session and expires the session cookie.

- **FAIL — Avoid account enumeration in response timing**
  - The login endpoint only performs the expensive `scryptSync` password derivation when the email exists:
    ```ts
    if (!account || password.length > 200 || !timingSafeEqual(... passwordHash(...))) ...
    ```
  - For a nonexistent email, `!account` short-circuits before hashing. For an existing email, `scryptSync` is executed.
  - This creates a measurable timing distinction between valid and invalid account identifiers, violating the requirement to avoid enumeration through response timing.

- **FAIL — Complete server-side validation of email input**
  - The server only normalizes the submitted email with:
    ```ts
    typeof data?.email === "string" ? data.email.trim().toLowerCase() : ""
    ```
  - It does not impose a maximum length or validate the expected email structure before account lookup.
  - The requirements explicitly require server-side validation of email input. Client-side `type="email"` is not sufficient because it can be bypassed.

- **PASS — Output handling and XSS posture**
  - Most UI strings are static.
  - User input is not reflected into the DOM.
  - Sensitive server-derived delivery-channel text is derived from controlled account records, not request input.
  - The CSP further reduces impact from script injection.

## FAILING_ITEMS

- **Login timing permits account enumeration**
  - Nonexistent-account login attempts bypass the expensive password hash calculation, while existing-account attempts perform `scryptSync`.
  - An attacker can potentially distinguish registered from unregistered emails based on response duration despite identical error text.

- **Email input is not fully validated server-side**
  - The authentication endpoint lacks an email format check and maximum-length constraint.
  - The endpoint should reject malformed or oversized email input before using it for account lookup.

## NEW_TASKS

1. **Make password verification timing uniform for existing and nonexistent accounts**
   - Add a fixed dummy password salt/verifier or perform a dummy `passwordHash()` operation when no account is found.
   - Always perform one comparable password-hash operation before returning the generic authentication failure response.
   - Preserve the same generic error message and status for invalid credentials.

2. **Add strict server-side email validation to `/api/authenticate`**
   - Define a bounded email validation helper, including a reasonable maximum length and a conservative email format check.
   - Normalize only after validating the input type and length.
   - Treat malformed email values exactly like invalid credentials to avoid creating a validation-based enumeration oracle.

## DECISION

FAIL