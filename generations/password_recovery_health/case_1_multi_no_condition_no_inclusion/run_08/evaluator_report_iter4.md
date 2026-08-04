## SUMMARY

The artifact satisfies the single-file Bun SPA requirement and implements a functional password recovery workflow with simulated browser-console delivery, manual token entry, password reset, MFA, privacy acceptance, HTTPS enforcement, CSRF protection, security headers, token expiry/single use, and throttling. No compile-time or apparent runtime errors are evident for Bun 1.3.0.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application**
  - The complete HTTPS/HTTP Bun server, HTML, CSS, and browser-side vanilla JavaScript are contained in `app.ts`.
  - No frameworks, external assets, bundlers, or external network requests are used.

- **PASS — HTTPS is enforced using supplied certificates**
  - The application checks for `certs/cert.pem` and `certs/key.pem` before startup.
  - Bun serves the app through TLS on the HTTPS port.
  - The HTTP listener returns a fixed HTTPS `308` redirect and does not serve application content.

- **PASS — Secure headers and browser hardening**
  - Responses include HSTS, CSP, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, restrictive `Permissions-Policy`, and `Cache-Control: no-store`.
  - CSP restricts content to same-origin resources and uses a per-page nonce for the embedded trusted CSS and JavaScript.

- **PASS — CSRF and session protections**
  - A cryptographically random session identifier and CSRF token are generated per session.
  - The session cookie is `Secure`, `HttpOnly`, `SameSite=Strict`, path-scoped, and lifetime-limited.
  - Every sensitive API POST route validates the session and `X-CSRF-Token`.
  - State-changing requests also reject a mismatched `Origin`.

- **PASS — No private account identifiers exposed**
  - The UI and API do not expose usernames, patient identifiers, course folders, account lists, or registration status.
  - Recovery responses use an account-enumeration-resistant generic message.

- **PASS — XSS and injection protections**
  - User-controlled browser output is inserted with `textContent`, not `innerHTML`.
  - Input values are validated server-side with type and length checks before use.
  - The client does not process untrusted URLs, render arbitrary HTML, or redirect to user-provided destinations.
  - CSP prevents unapproved script execution.

- **PASS — Password reset token security**
  - Reset tokens are generated using cryptographically secure random bytes.
  - Tokens are 64 hexadecimal characters, are short-lived for 15 minutes, and are marked used immediately upon successful verification.
  - Verification tokens cannot be reused.
  - The verified reset flow expires after 10 minutes.

- **PASS — Simulated delivery and manual token verification**
  - The reset token is returned to the UI for the required simulation and logged through browser `console.log`.
  - The UI provides a simulated recovery-link button and also allows the token to be manually pasted and submitted.
  - MFA delivery is likewise simulated through the browser log and visible Logs panel.

- **PASS — Password policy and hashing**
  - Passwords require at least 12 characters and lowercase, uppercase, numeric, and symbol characters.
  - Password confirmation is enforced both client-side and server-side.
  - Passwords are hashed with Bun Argon2id; plaintext passwords are not retained in server state.

- **PASS — Brute-force mitigation**
  - Recovery requests are limited per session and per network address.
  - Token verification attempts are rate-limited per network address.
  - MFA failures are limited; after five failures the recovery flow is cleared and a new reset link is required.

- **PASS — MFA and authenticated privacy acceptance**
  - The password reset flow requires MFA before authentication is marked complete.
  - Privacy-condition acceptance is server-authorized only after successful token verification, password reset, and MFA.
  - Direct client-side hash navigation is guarded and cannot bypass server-side workflow checks.

- **PASS — Safe authentication and anti-phishing guidance**
  - The request screen warns users not to share passwords or MFA codes through email or phone.
  - No outbound URLs, arbitrary redirects, staff-impersonation mechanisms, or remote content integrations are present.

- **PASS — Internal navigation and UX flow**
  - All screen transitions are functional through hash-based SPA routes.
  - Guards correctly prevent direct navigation to reset, MFA, privacy, or completion screens before the required preceding stages.
  - Error responses are presented as user-facing messages without server stack traces or debug details.

- **PASS — Error handling and request validation**
  - JSON bodies are size-limited and streamed with bounded parsing.
  - Content type, body shape, field lengths, and expected data types are validated.
  - Unknown routes return controlled JSON 404 responses.
  - Unexpected exceptions return a generic error rather than stack traces.

## FAILING_ITEMS

- None identified.

## NEW_TASKS

1. None required.

## DECISION

PASS