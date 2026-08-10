## SUMMARY

The artifact is a single-file Bun/TypeScript application that serves a functional HTTPS password-recovery SPA with inline CSS and vanilla browser JavaScript. It implements recovery-token verification (manual entry and simulated-link action), password reset, MFA, privacy acceptance, and appointment confirmation. Security controls—including session-bound CSRF protection, CSP nonces, secure cookies, password hashing, throttling, route authorization, and restrictive security headers—are present and the code appears syntactically and logically valid for Bun 1.3.0.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun server and SPA delivery:** The server, HTML template, CSS, and browser-side JavaScript all reside in `app.ts`. It uses `Bun.serve` directly and does not require bundlers, frameworks, build tools, or external assets.

- **PASS — HTTPS/TLS configuration:** `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`. Requests are additionally rejected unless their URL protocol is HTTPS.

- **PASS — Password recovery flow works:** A user can request a recovery code, verify it manually, or use the simulated-link button, then set a new password and complete MFA.

- **PASS — Mock delivery is available in browser console and UI:** Recovery tokens and MFA codes are logged through the browser-side `console.log` function. The recovery code is also shown in the visible, browser-rendered Logs panel. This satisfies the explicit mock-testing requirement.

- **PASS — Manual verification code submission:** The verification screen provides a text input for manual reset-token entry and submits it to `/api/recovery/verify`.

- **PASS — Internal navigation functions:** Hash-based internal navigation is implemented, and `/api/session` only permits valid state transitions. Attempts to skip ahead are redirected to the appropriate current step.

- **PASS — ADHD/inclusivity-focused UX:** The flow has visible progress indicators, one clear action per stage, consistent language, accessible help/safety details, no visible countdown timers, clear feedback, a low-distraction layout, and wording that users can pause and return.

- **PASS — Session and CSRF protection:** Session cookies are `HttpOnly`, `Secure`, `SameSite=Strict`, and use random session IDs. CSRF tokens are unique per session and validated for every POST endpoint before sensitive actions occur.

- **PASS — Access-control enforcement:** Sensitive API actions enforce state prerequisites:
  - Password reset requires a current verified recovery record.
  - Privacy acceptance requires authentication.
  - Appointment confirmation requires authentication plus privacy acceptance.
  - Route rendering is server-state controlled rather than trusted from the URL hash.

- **PASS — Reset-token security:** Reset tokens are generated with cryptographically secure random bytes, stored only as SHA-256 hashes, expire after 10 minutes, have verification-attempt limits, and are consumed before the password-hash operation to prevent reuse during concurrent requests.

- **PASS — Password security:** Passwords are never stored in plaintext. Initial and reset passwords are bcrypt hashed through `Bun.password.hash`, and login compares through `Bun.password.verify`. The password policy requires 12–128 characters, uppercase, lowercase, numeric, and symbol characters.

- **PASS — MFA implementation:** MFA is required after both login and password reset. MFA codes expire, have attempt limits, and lock after repeated failures. Deterministic mock delivery is consistent with the requirement for deterministic mock values.

- **PASS — Brute-force mitigation:** Login attempts are tracked and locked after five failures. Recovery-token and MFA-code verification also lock after five unsuccessful attempts.

- **PASS — XSS/injection protection:** The browser UI constructs DOM with `document.createElement` and assigns user-visible strings with `textContent`; it does not interpolate user input into HTML. The server does not reflect arbitrary user input in responses. CSP restricts scripts and styles to cryptographic nonces.

- **PASS — Security headers and production-safe error handling:** HSTS, CSP, frame protections, MIME sniffing protection, referrer policy, permissions policy, and no-cache headers are set. Generic error responses avoid exposing stack traces or debug details.

- **PASS — No external calls, open redirects, or SSRF path:** Browser requests are same-origin only. No user-supplied URL is fetched, redirected to, or otherwise used as an outbound destination.

- **PASS — Safe-authentication guidance:** The UI prominently states that staff will never ask for passwords or verification codes by email or phone, and help text reinforces that codes should only be entered in the portal.

## FAILING_ITEMS

- None identified.

## NEW_TASKS

1. No remediation tasks required.

## DECISION

PASS