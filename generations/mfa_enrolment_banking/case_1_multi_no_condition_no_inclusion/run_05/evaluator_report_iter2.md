## SUMMARY

The artifact is a well-structured single-file Bun application with responsive mobile UI, inline client logic, HTTPS/TLS configuration, CSP nonces, CSRF checks, encrypted TOTP storage, hashed recovery codes, and working simulated TOTP/recovery-code flows. However, it does not securely authenticate an account owner before granting access to an account, and its identity verification code is a fixed deterministic value rather than a securely generated verification value. These are material failures against the access-control and authentication requirements.

## FUNCTIONAL_CHECK

- **Single `app.ts` artifact with Bun server, inline HTML/CSS/JS, no framework/build tooling/external assets — PASS**
  - The complete application is contained in one TypeScript file.
  - It uses `Bun.serve`, embeds the page template and client JavaScript, and has no external asset or network dependency.

- **TLS/HTTPS enforcement using provided certificate paths — PASS**
  - Bun is configured with `certs/cert.pem` and `certs/key.pem`.
  - Requests not using an `https:` URL are rejected.
  - HSTS is sent in security headers.

- **Mobile-responsive, semantic, legible SPA UI — PASS**
  - The page has a mobile viewport meta tag, constrained mobile-width shell, responsive layout, accessible labels, visible focus styling, and semantic `main`, `header`, `section`, `nav`, `form`, and heading elements.
  - Hash routes for sign-in, identity verification, setup, confirmation, recovery, and logout are implemented.

- **Simulated OTP, authenticator provisioning, verification, and recovery-code flows work — PASS**
  - Identity verification, TOTP provisioning, TOTP verification, recovery-code use, and recovery-code regeneration have corresponding UI and API routes.
  - The browser logs test values via `console.log`.
  - The TOTP algorithm is implemented on both server and browser and is compatible with the displayed Base32 secret/provisioning URI.
  - Recovery codes are returned after enrolment and can be used once.

- **Manual authenticator setup support — PASS**
  - The provisioning endpoint returns a manual Base32 secret and an `otpauth://` provisioning URI.
  - The UI displays the manual secret and permits manual entry of an authenticator-generated OTP.

- **Server-side authorization and IDOR prevention — FAIL**
  - The sign-in endpoint accepts any syntactically valid email address and derives the account identity directly from that client-supplied value.
  - An unauthenticated attacker can submit a victim's known email address, receive the fixed identity code (`654321`), and obtain a session for the account derived from that email.
  - This allows the attacker to provision a replacement authenticator and regenerate recovery codes for another account. The session is technically bound to an account, but the application does not establish that the requester owns that account.

- **CSRF protection on state-changing endpoints — PASS**
  - State-changing authenticated routes require a session-bound CSRF token.
  - Requests containing `userId` or `accountId` are rejected by `stateChangingValid`.
  - Session cookies use `SameSite=Strict`, which adds defense in depth.

- **Secure response headers and restrictive CORS — PASS**
  - CSP with per-page nonce, `frame-ancestors 'none'`, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, and `Cache-Control: no-store` are present.
  - CORS is restricted to localhost TLS origins and credentialed CORS responses vary by `Origin`.
  - Generic error handling avoids exposing stack traces.

- **Secure session handling — PASS**
  - Session IDs are generated with `crypto.getRandomValues`.
  - Sessions are rotated on sign-in.
  - Cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - Idle and absolute server-side timeouts are enforced.
  - Logout invalidates the server session and expires the cookie.

- **Secret storage and cryptographic handling — PASS**
  - TOTP secrets are AES-GCM encrypted at rest in server memory.
  - Recovery codes are stored only as pepper-protected SHA-256 hashes.
  - TOTP secrets and recovery codes are generated using cryptographically secure randomness.
  - No secrets or session values are persisted in browser storage or non-HttpOnly cookies.

- **Input validation and XSS/injection controls — PASS**
  - Email, OTP, and recovery-code input formats are validated server-side.
  - JSON request sizes are limited.
  - No SQL/database layer exists, so there are no unparameterized SQL queries.
  - Client-side dynamic content is rendered with `textContent` and DOM APIs rather than unsafe HTML interpolation.
  - Redirects are constrained to an internal hash-route allow-list.

- **Verification-code entropy, expiry, single-use behavior, and rate limiting — FAIL**
  - The identity verification code is hard-coded as `"654321"` rather than generated with a cryptographically secure RNG.
  - Although it is hashed, time-bound, and marked single-use, its fixed value has no entropy and is known to all users/attackers.
  - TOTP and recovery-code failures are rate limited, but the predictable identity code defeats the identity-verification control.

- **Code validity / direct Bun execution — PASS**
  - No evident TypeScript syntax errors or broken imports are present.
  - The APIs used (`Bun.serve`, `Bun.file`, Web Crypto, `Buffer`) are available in Bun 1.3.0.
  - Client and server logic are self-contained and directly executable by Bun without compilation.

## FAILING_ITEMS

- **Email-only sign-in grants account access without proving account ownership.**
  - `POST /api/signin` accepts a client-controlled `email`.
  - `accountIdForIdentity(body.email)` deterministically chooses the target account from that email.
  - The server returns the identity code to the caller and always uses the same value, so any party who knows a target email can complete identity verification and modify that account's MFA configuration.
  - This violates the requirements for server-side account-owner authorization, IDOR resistance, and secure authentication.

- **The identity verification OTP is predictable and not securely generated.**
  - `account.identityHash = await protectedHash("654321")` uses a fixed value.
  - The API explicitly returns `testCode: "654321"` to every sign-in caller.
  - This fails the requirement that verification codes/OTPs be generated with sufficient entropy.

## NEW_TASKS

1. **Replace email-selected authentication with server-validated account ownership.**
   - Do not derive `session.userId` solely from `body.email`.
   - Introduce a server-side authenticated-principal mechanism before assigning an account to a session. In this demo, use a fixed trusted test principal/session fixture or a server-validated mock credential flow, rather than allowing a caller to choose an arbitrary email/account.
   - Ensure MFA provisioning, verification, recovery-code use, and regeneration always derive the account solely from that validated session principal.

2. **Generate a cryptographically secure, per-sign-in identity verification code.**
   - Replace the hard-coded `"654321"` value with a CSPRNG-generated six-digit code.
   - Hash only the generated code server-side, retain its expiry and single-use behavior, and bind it to the authenticated account/session.
   - For the required demo behavior, return/log the generated test code only after the server has established the authenticated test principal, rather than making a universal code available to anyone who submits an email.

## DECISION

**FAIL**