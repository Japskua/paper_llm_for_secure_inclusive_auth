## SUMMARY

The artifact meets the single-file Bun SPA requirement and implements a functional, accessible password recovery and privacy-acceptance flow. It uses HTTPS with the specified certificate paths, server-side sessions and CSRF validation, bcrypt password/token hashing, throttling, MFA simulation, secure route-state enforcement, and browser-console mock delivery logging. No concrete runtime, syntax, or security-blocking defects were identified from the provided code.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application:** The server, HTML, CSS, and browser JavaScript are all contained in `app.ts`. It runs directly with Bun and does not rely on bundlers, frameworks, external assets, or external network calls.

- **PASS — HTTPS and supplied certificates:** `Bun.serve` is configured with TLS using `certs/cert.pem` and `certs/key.pem`, and the application is served as HTTPS-only on `localhost:3000`.

- **PASS — Password recovery flow works:** Users can request a code, manually submit it, set a policy-compliant replacement password, and accept privacy conditions.

- **PASS — Simulated recovery delivery is testable:** Recovery tokens are cryptographically random, returned in the mock API response, logged through browser-side `console.log`, and displayed in the in-page simulated logs panel.

- **PASS — Manual code entry is supported:** The verification screen includes a recovery-code form. It also supports a token supplied through the hash route format if one is used.

- **PASS — Authentication and MFA flow works:** Normal sign-in requires password verification followed by MFA code verification. The deterministic MFA test code is exposed only as a browser-side mock for testing.

- **PASS — Strong password policy:** New passwords require at least 12 characters, uppercase and lowercase letters, a number, and a symbol. Passwords are confirmed before replacement.

- **PASS — Passwords and reset tokens are not stored in plaintext:** Account passwords and reset/MFA values are stored and verified using Bun bcrypt password APIs. Reset tokens are random and only token hashes are persisted server-side.

- **PASS — Reset-token security:** Reset tokens are random, session-bound, expire after 15 minutes, are single-use after successful verification, and have failed-attempt lockout behavior.

- **PASS — CSRF protection:** A unique CSRF token is created per server session, embedded in the initial HTML response, sent in the `X-CSRF-Token` header, and validated for every POST mutation. Origin validation is also applied when an Origin header is present.

- **PASS — Session and access control:** Sessions use opaque, `HttpOnly`, `Secure`, `SameSite=Strict` cookies. Recovery records are tied to the issuing session, and protected state transitions are validated server-side rather than relying on client routing.

- **PASS — Brute-force mitigation:** Login, recovery-request, recovery-code, and MFA-code attempts have throttling or lockout protections.

- **PASS — XSS/injection protections:** Inputs are bounded and validated server-side. User-facing dynamic text is escaped before insertion into `innerHTML`. Client script and stylesheet execution are constrained using CSP nonces.

- **PASS — Secure response headers:** The application sets HSTS, CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, restrictive Permissions Policy, cache prevention, and cross-origin isolation-related headers.

- **PASS — No account enumeration through recovery response:** The recovery-request response uses the same generic wording whether or not the account exists.

- **PASS — No sensitive identifier exposure:** The UI does not display usernames, patient data, account details, or internal record IDs. Recovery state is server-side and opaque to the browser.

- **PASS — Safe authentication guidance / anti-social-engineering UX:** Help content consistently tells users not to share passwords or recovery codes and to use known hospital contact details rather than unexpected messages.

- **PASS — Accessible, low-stress ADHD-oriented flow:** The UI uses clear step wording, visible progress, “Next” reminders, calm layout, minimal distraction, accessible focus styles, persistent help, no unexpected navigation, and pause/resume functionality.

- **PASS — Pause and resume:** Recovery progress is held in the server session and can be paused and resumed from the prior stage. The secure reset token still remains short-lived, as required.

- **PASS — Internal SPA navigation:** Hash-based login, MFA, recovery, code verification, password, privacy, confirmation, pause, and help links are supported. Server-backed route gating redirects users to the valid next step.

- **PASS — Production-safe error handling:** The server catches unexpected errors and returns a generic response without exposing stack traces or debug details.

## FAILING_ITEMS

- None identified.

## NEW_TASKS

1. No changes required.

## DECISION

**PASS**