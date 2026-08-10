## SUMMARY

The artifact satisfies the MFA enrolment, security, mobile UX, single-file, and Bun/TLS requirements. It implements a functional simulated sign-in, TOTP provisioning and verification flow, MFA activation, recovery-code generation/regeneration/consumption, secure session handling, CSRF validation, authorization checks, secure headers, and browser-only mock-value logging. No blocking syntax or runtime defects are apparent from the submitted code.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no frameworks, build tools, external assets, or network calls.**  
  The entire server, HTML, CSS, and browser JavaScript are contained in `app.ts`. It uses `Bun.serve`, standard Web APIs, inline HTML/CSS/JS, and no imports or external requests.

- **PASS — TLS/HTTPS is configured using the required certificate paths.**  
  `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`, and the application advertises an HTTPS localhost URL.

- **PASS — Responsive, mobile-legible SPA UI.**  
  The page includes a viewport meta tag, a constrained mobile-friendly content width, responsive media rules, readable controls, semantic forms, labels, and touch-friendly full-width buttons.

- **PASS — Identity verification/sign-in flow works with deterministic mock credentials.**  
  The browser submits the supplied email and phone values to `/api/auth/signin`; the server validates them and creates a new authenticated session. Invalid input receives a generic error and a minimum response duration is applied.

- **PASS — TOTP authenticator provisioning and manual secret entry are supported.**  
  `/api/mfa/provision` generates a cryptographically random Base32 shared secret. The UI displays the manual setup secret, allowing it to be entered into an authenticator application without requiring a QR code.

- **PASS — Simulated OTP verification works and is browser-console logged.**  
  Provisioning returns a current deterministic TOTP test value to the browser. The browser logs the secret and current OTP using `console.log`, as required for testing. The server verifies the OTP against the encrypted secret.

- **PASS — OTP verification is time-bound and single-use for enrolment.**  
  TOTP values use a 30-second period. Once verification succeeds, `verification.used` prevents replaying the enrolment verification state to activate MFA again.

- **PASS — Recovery codes are generated securely, displayed for storage, and logged in the browser console.**  
  Ten cryptographically generated recovery codes are returned after activation and after regeneration. They are displayed in the UI and logged only through the browser console.

- **PASS — Recovery codes are stored securely and consumed once.**  
  The server stores only SHA-256 hashes of recovery codes combined with a server-side pepper. On successful verification, the matching hash is removed, making the recovery code single-use.

- **PASS — Recovery-code regeneration and verification function correctly.**  
  Authenticated users can regenerate recovery codes with CSRF protection. Recovery-code verification accepts valid codes, consumes them, and reports the remaining count.

- **PASS — Server-side authorization prevents IDOR-style account manipulation.**  
  MFA endpoints derive account identity exclusively from the opaque server-side session. Request bodies containing `id`, `uid`, `userId`, or `accountId` are rejected, and URL query parameters with those identifiers cause authorization failure.

- **PASS — CSRF protection is applied to authenticated state-changing MFA operations.**  
  Session-specific CSRF tokens are generated server-side and required for logout, provisioning, OTP verification, MFA activation, trusted reset, recovery-code regeneration, and recovery-code verification.

- **PASS — Secure session-cookie settings are present.**  
  The session cookie uses `HttpOnly`, `Secure`, `SameSite=Strict`, a scoped path, and an absolute expiration. The session token is never exposed to browser JavaScript.

- **PASS — Session fixation, timeout, and logout handling are implemented.**  
  A successful sign-in deletes any existing session token and creates a new random session identifier. The server enforces idle and absolute timeouts, and logout invalidates the server session and clears the cookie.

- **PASS — Failed verification attempts are rate-limited and locked out.**  
  Sign-in failures are tracked with a rolling time window and temporary lockout. MFA OTP failures lock the user after repeated attempts. Recovery-code failures lock recovery verification after five failures.

- **PASS — Sensitive information is not written to server logs, URL parameters, browser storage, or non-HttpOnly cookies.**  
  The server logs only its listening address. Session tokens remain HttpOnly cookies. No use of `localStorage` or `sessionStorage` exists. Secrets and mock OTP/recovery values are intentionally logged in the browser console per the explicit testing requirement.

- **PASS — Secure HTTP response headers are implemented.**  
  Responses include CSP with nonce-based inline script/style authorization, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, CSP `frame-ancestors 'none'`, referrer policy, permissions policy, and `Cache-Control: no-store`.

- **PASS — CORS is restricted to explicit trusted localhost HTTPS origins.**  
  The server only emits credentialed CORS headers for the configured `https://localhost`, `https://127.0.0.1`, and `https://[::1]` origins using the application port.

- **PASS — Server-side input validation and safe output handling are present.**  
  Email, phone, OTP, and recovery-code inputs are validated. The UI does not interpolate untrusted values through HTML strings; secrets and recovery-code values are assigned with `textContent`, avoiding DOM XSS.

- **PASS — Generic errors and production-safe error handling are used.**  
  API failures return generic messages rather than stack traces or sensitive diagnostics. The server fetch handler catches unexpected errors and returns a generic response.

- **PASS — No open redirects or external/internal navigation defects are present.**  
  The application does not accept redirect targets and does not depend on broken internal links; it uses SPA state transitions and same-origin API requests.

## FAILING_ITEMS

- None identified.

## NEW_TASKS

1. No changes required.

## DECISION

**PASS**