## SUMMARY

The artifact is a single-file Bun/TypeScript password-recovery SPA that serves inline semantic HTML, CSS, and vanilla JavaScript over TLS. It implements a complete simulated recovery flow—recovery token, MFA, password reset, sign-in, privacy acceptance, and appointment confirmation—with server-side session state, CSRF validation, secure headers, session-bound authorization, bcrypt password hashing, and browser-side simulated delivery logs. No blocking syntax, runtime, routing, or security-flow defects were identified.

## FUNCTIONAL_CHECK

- **PASS — Single-file deliverable and zero-compilation compliance:** The server, HTML template, CSS, and browser JavaScript are all contained in `app.ts`. It runs directly with Bun and uses no frameworks, bundlers, build tools, package imports, or external assets.

- **PASS — Bun TLS server uses the supplied certificate paths:** The app checks for `certs/cert.pem` and `certs/key.pem`, terminates rather than running insecurely when they are absent, and configures `Bun.serve` with those TLS files.

- **PASS — HTTPS enforcement:** The portal itself is served over HTTPS on port 3000. A separate HTTP endpoint only returns a `308` redirect to the HTTPS portal and does not serve application content over plaintext HTTP.

- **PASS — Full password recovery UX works:** The UI supports recovery request, manual reset-token entry, MFA entry, password creation, sign-in confirmation, privacy-condition acceptance, appointment confirmation, and completion feedback.

- **PASS — Simulated reset delivery is available in the browser:** The reset token is returned to the UI response, written to the browser console via `console.log`, and represented in the visible simulated log panel. The MFA code is also returned to the browser and logged/displayed for testing.

- **PASS — Manual verification-code submission is supported:** The recovery token and MFA code are entered manually through dedicated form fields.

- **PASS — Internal progression/navigation functions correctly:** The SPA uses server-controlled `phase` state and renders each recovery stage only after the prior authorized action succeeds. No broken internal routes or inaccessible screens are present.

- **PASS — CSRF protection is implemented:** A cryptographically random CSRF token is generated per server-side session, sent during bootstrap, and validated on every state-changing API request using a timing-safe comparison.

- **PASS — Sensitive actions enforce server-side authorization and workflow order:** Password reset, sign-in, privacy acceptance, and appointment booking check server-owned session state, authentication state, and phase. Client-supplied identifiers are not used to select protected records, preventing IDOR-style access.

- **PASS — Session security is implemented:** Sessions use opaque random IDs stored in `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/` cookies. Session expiration is enforced server-side and expired sessions are cleaned up.

- **PASS — Password reset tokens are secure for the simulated environment:** Tokens are cryptographically random, session-bound, short-lived, validated with a timing-safe comparison, invalidated after successful use, and cannot be reused.

- **PASS — MFA is implemented:** A second-factor code step is required after successful reset-token verification and before password reset. The deterministic code is appropriate to the explicit simulation/testing requirement.

- **PASS — Brute-force controls are implemented:** Recovery-token verification, MFA verification, password policy failures, recovery initiation, and sign-in attempts are throttled after repeated failures.

- **PASS — Password policy and storage meet requirements:** Passwords require at least 12 characters, upper- and lowercase letters, a number, and a symbol; common/repetitive passwords are rejected. Passwords are hashed with bcrypt using `Bun.password.hash` and are not logged or stored in plaintext.

- **PASS — XSS/input-handling protections are implemented:** Inputs are validated server-side with strict allowlists and length limits. Dynamic browser output is written through `textContent`, `createElement`, and `replaceChildren`; no user-controlled content is inserted with `innerHTML`.

- **PASS — CSP and browser security headers are configured:** The app sets HSTS, nonce-based CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, and no-store cache headers.

- **PASS — No external network calls, open redirects, or SSRF-capable URL handling:** Browser API requests are same-origin only. The application accepts no user-provided outbound URLs and has no third-party resources.

- **PASS — Phishing/social-engineering guidance is present:** The UI tells users not to share passwords through email/support contacts and to verify the localhost hospital address before entering credentials.

- **PASS — Private data is not exposed:** The portal has no patient records, usernames, course folders, account identifiers, appointment identifiers, directory listing, stack traces, or debug output exposed to the browser.

- **PASS — Error handling is production-safe:** Server errors are caught and converted to a generic `503 Service unavailable` response without exposing stack traces or implementation details.

- **PASS — Semantic and accessible UI structure is present:** The page uses `header`, `main`, `section`, `aside`, `footer`, labeled inputs, forms, alert roles, visible focus styling, and status messaging.

## FAILING_ITEMS

- None identified.

## NEW_TASKS

1. No remediation tasks required.

## DECISION

PASS