## SUMMARY

The artifact is a valid single-file Bun password-recovery SPA with inline HTML, CSS, and vanilla browser JavaScript. It uses TLS with the supplied certificate paths, server-side sessions, per-session CSRF protection, secure cookies, CSP nonces, reset-token expiry/single-use behavior, bcrypt hashing, MFA simulation, rate limits, and server-enforced progression through privacy acceptance and appointment confirmation. No functional or security-blocking code errors were identified.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun implementation with no build tooling**
  - The entire server, HTML template, CSS, and browser-side JavaScript are contained in `app.ts`.
  - It uses `Bun.serve()` directly and does not depend on frameworks, bundlers, external scripts, external stylesheets, or network services.

- **PASS — HTTPS is enforced**
  - The main application is served through TLS on port `3000` with `certs/cert.pem` and `certs/key.pem`.
  - Requests not received as local HTTPS requests are rejected with HTTP `421`.
  - A separate HTTP listener returns `426 HTTPS is required` and does not provide application routes or cookies.

- **PASS — Secure security headers and CSP**
  - Responses include HSTS, CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, COOP, CORP, and no-store cache headers.
  - The CSP uses a per-response nonce for the inline `<style>` and `<script>`.
  - CSP blocks external/default resources, framing, object embedding, non-self form submission, and untrusted scripts.

- **PASS — CSRF protection and session protection**
  - Sensitive API routes require both a valid server-side session and a matching `X-CSRF-Token`.
  - CSRF validation also requires an allowed HTTPS localhost origin.
  - The session cookie is `Secure`, `HttpOnly`, `SameSite=Strict`, host-only through the `__Host-` naming convention, and scoped to `/`.
  - CSRF tokens are generated uniquely per session.

- **PASS — Sensitive server-side access control**
  - Privacy acceptance requires an authenticated session.
  - Appointment confirmation requires both authentication and accepted privacy conditions.
  - Client-side screen navigation does not bypass server-side authorization because sensitive API routes independently validate state.

- **PASS — Password-reset token security**
  - Reset tokens are generated with cryptographically secure random bytes.
  - Tokens are session-bound, expire after 15 minutes, and are invalidated after password update.
  - A new reset request replaces the old token for the known mock account.
  - Invalid, expired, and previously used codes receive a clear error response.

- **PASS — Manual reset-code submission**
  - The UI provides an explicit “Enter reset code” screen.
  - The simulated reset token is returned to the UI and logged using browser-side `console.log`.
  - Users can paste or manually type the code to continue.

- **PASS — Simulated delivery is browser-visible and does not call external services**
  - Reset and MFA mock values are displayed in the local logs panel and emitted with browser `console.log`.
  - No email, SMS, third-party API, or other external network call is used.

- **PASS — Account enumeration protections**
  - Reset-request responses use a generic message regardless of account eligibility.
  - The UI does not reveal usernames, patient data, or account existence.
  - For unknown addresses, a nonfunctional opaque token is still returned, while only the known mock account retains a valid server-side token.

- **PASS — Brute-force throttling**
  - Reset-request attempts are limited to three per 15 minutes per session.
  - Reset-token guesses are limited to five per 15 minutes per session.
  - MFA attempts are limited to five per 15 minutes per session.

- **PASS — Strong password policy and password hashing**
  - The password policy requires at least 12 characters, upper- and lowercase letters, a digit, a symbol, and no whitespace.
  - The same policy is checked both in the browser and on the server.
  - Passwords are hashed server-side using Bun bcrypt with cost `12`.
  - Password values are neither logged nor returned in API responses.

- **PASS — MFA is implemented and enforced**
  - Password reset completion requires an MFA step before authentication is granted.
  - MFA codes expire after 15 minutes and are invalidated after successful verification.
  - The mock MFA code is logged in the browser and can be manually submitted.

- **PASS — XSS and output-safety protections**
  - Dynamic UI content is rendered via DOM APIs and `textContent`, rather than by assigning untrusted HTML.
  - Browser-provided data and server messages are not inserted with `innerHTML`.
  - Input is validated server-side before it affects sensitive actions.
  - The CSP substantially limits impact from script injection attempts.

- **PASS — Phishing and social-engineering guidance**
  - The UI prominently tells users to verify the local HTTPS portal and never share passwords, reset links, or verification codes through email, phone, or chat.
  - It explicitly states that hospital staff will not request those secrets.

- **PASS — Internal flow navigation works**
  - Request reset, reset-code verification, password update, MFA, privacy acceptance, and appointment confirmation screens all have functional navigation and server interactions.
  - The final appointment action is disabled after successful confirmation.

- **PASS — Error handling does not expose internal diagnostics**
  - Server exceptions return a generic error response.
  - Stack traces, directory listings, and debug information are not exposed to the browser.

## FAILING_ITEMS

- None identified.

## NEW_TASKS

1. No remediation tasks are required.

## DECISION

PASS