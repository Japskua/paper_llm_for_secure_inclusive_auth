## SUMMARY

The artifact is a valid single-file Bun/TypeScript MFA enrolment SPA. It serves responsive inline HTML/CSS/vanilla JavaScript over TLS, implements the complete sign-in, identity confirmation, TOTP provisioning and verification, recovery-code management, and logout flow. Server-side session ownership, CSRF validation, encryption at rest, rate limiting, replay prevention, secure headers, and generic error handling are implemented. No compilation step, framework, external asset, browser storage, or external network call is used.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no build tooling**
  - The server, HTML template, CSS, and client-side JavaScript are all contained in `app.ts`.
  - It uses Bun directly via `Bun.serve(...)`, imports only Node-compatible built-ins, and does not require a bundler, framework, compiler pipeline, or external assets.

- **PASS — TLS/HTTPS is configured**
  - The server reads and uses `certs/cert.pem` and `certs/key.pem` in `Bun.serve({ tls: { cert, key } })`.
  - Requests marked by a proxy as `x-forwarded-proto: http` are rejected.
  - HSTS is applied to responses.

- **PASS — Mobile-responsive SPA UI**
  - The document includes a correct mobile viewport meta tag.
  - Layout is constrained to a mobile-friendly maximum width and remains usable at narrow viewport sizes.
  - Forms use appropriate input types and `inputmode="numeric"` for OTP entry.

- **PASS — MFA enrolment flow is functional**
  - The UI supports sign-in, identity confirmation, authenticator setup, TOTP verification, MFA confirmation, recovery-code viewing, recovery-code regeneration, recovery-code consumption, and logout.
  - Client routing is state-based and the internal `Cancel`, `Back`, and logout controls have functional handlers.
  - The server validates flow state, such as requiring identity confirmation before setup and preventing setup after MFA has been enabled.

- **PASS — Manual authenticator provisioning is supported**
  - The server generates a Base32 TOTP secret.
  - The client displays the secret manually, together with TOTP parameters: SHA-1, six digits, and 30-second period.
  - No QR code is offered, so the manual-secret path fully satisfies the provisioning requirement.

- **PASS — Mock OTP and recovery-code verification works**
  - The current TOTP code is calculated from the generated secret and returned to the UI for the assessment flow.
  - The client logs simulated TOTP and recovery-code delivery using browser `console.log`.
  - Recovery codes can be verified and are consumed after successful use.

- **PASS — Server-side authorization and IDOR prevention**
  - MFA endpoints derive account ownership exclusively from the HttpOnly session cookie through `authenticatedSession`.
  - Request bodies reject `accountId` and `userId`, preventing client-controlled account selection.
  - Every MFA settings endpoint requires an authenticated session, and the session’s `accountId` must match the server-side account.

- **PASS — CSRF protection for state-changing operations**
  - Sign-in, identity confirmation, setup, TOTP verification, recovery-code regeneration, recovery-code verification, and logout require a valid CSRF token.
  - CSRF tokens are cryptographically random and associated with each server-side session.
  - Session cookies use `SameSite=Strict`.

- **PASS — Secure session handling**
  - Session identifiers are cryptographically random.
  - The pre-authentication session is deleted and replaced with a new authenticated session at sign-in, preventing session fixation.
  - Authenticated sessions have idle and absolute expiry checks.
  - Logout invalidates the server-side session and clears the cookie.

- **PASS — Secure cookie configuration**
  - Session cookies include `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, and a bounded `Max-Age`.
  - Session tokens are not stored in `localStorage`, `sessionStorage`, or client-readable cookies.

- **PASS — Required security headers and restricted CORS**
  - Responses include CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, `Permissions-Policy`, and `Cache-Control: no-store`.
  - CSP restricts script/style execution to the server-generated nonce and same-origin resources.
  - CORS only reflects trusted localhost TLS origins and uses `Vary: Origin`.

- **PASS — Encryption and secure randomness**
  - TOTP secrets and recovery-code records are stored encrypted with AES-256-GCM.
  - Keys, session IDs, CSRF tokens, authenticator secrets, and recovery-code material are generated with `randomBytes`.
  - TOTP generation uses HMAC-SHA-1 as specified by standard TOTP compatibility requirements.

- **PASS — OTP time bounds, replay resistance, and lockout**
  - TOTP verification accepts only a narrow current/adjacent 30-second counter window.
  - `acceptedCounter` prevents reuse of an already accepted TOTP counter.
  - Recovery codes are deleted after successful verification.
  - Failed TOTP and recovery-code attempts are rate-limited and trigger a 10-minute lockout after five failures.

- **PASS — Input validation and safe client rendering**
  - Email, phone, OTP, and recovery-code inputs are validated server-side with type, length, and format checks.
  - JSON requests are constrained to a small body size and reject account/user identifiers.
  - Dynamic client output containing secrets or codes uses `textContent` and `createElement`, not unsafe interpolation into `innerHTML`.
  - The static `innerHTML` templates do not include user-controlled values.

- **PASS — Error handling and anti-enumeration messaging**
  - Sign-in and identity failures return generic messages rather than indicating whether a particular account detail exists.
  - Top-level request handling catches unexpected errors and returns a generic error response rather than stack traces.

## FAILING_ITEMS

- None identified.

## NEW_TASKS

1. No changes required.

## DECISION

PASS