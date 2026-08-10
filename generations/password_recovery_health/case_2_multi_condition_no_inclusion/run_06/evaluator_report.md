## SUMMARY

The artifact meets the specified password recovery, security, UX, and deployment requirements. It is a single `app.ts` file containing the Bun HTTPS server and a vanilla HTML/CSS/JavaScript SPA. The recovery flow is functional end-to-end, uses browser-console mock delivery, supports both recovery-link and manual token verification, applies CSRF protection, enforces staged authorization, throttles repeated attempts, hashes passwords with bcrypt, and sets appropriate security headers.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun implementation**
  - The complete application, including server, HTML, CSS, and browser JavaScript, is contained in `app.ts`.
  - It uses Bun directly and does not require a bundler, compiler, framework, external asset, or external network request.

- **PASS — HTTPS and provided TLS certificates**
  - Bun is configured with `tls.cert` and `tls.key` using `certs/cert.pem` and `certs/key.pem`.
  - The application refuses to start when either certificate file is absent.
  - No non-TLS HTTP application server is created.

- **PASS — Recovery initiation flow**
  - The recovery form is rendered in the SPA and accepts an email address.
  - The server returns a generic response regardless of account availability, reducing account-enumeration disclosure.
  - A test-only reset token is returned to the UI and logged through `console.log` in the browser as required.

- **PASS — Verification link and manual token entry**
  - The recovery delivery UI generates a functioning internal hash link to `#verify?token=...`.
  - The token is also prefilled into the manual verification form.
  - Users can manually type or submit a token without relying on the link.

- **PASS — Token security**
  - Reset tokens are generated using `crypto.getRandomValues`.
  - Tokens are 64 hexadecimal characters, hashed server-side with SHA-256, short-lived for 15 minutes, and single-use.
  - The raw token is cleared from the recovery record after successful verification.
  - Tokens are placed in a URL fragment rather than a server-visible query string, avoiding token exposure in HTTP requests and referrers.

- **PASS — CSRF prevention**
  - A unique 64-character CSRF token is created per server-side session.
  - State-changing API calls require the CSRF value in both the request header and JSON body.
  - The server rejects missing or invalid sessions, bodies, and CSRF values with HTTP 403.

- **PASS — Session and access control**
  - Session identifiers are cryptographically random and stored in `HttpOnly`, `Secure`, `SameSite=Strict` cookies.
  - Recovery records are bound to the initiating session through `recovery.sessionId`.
  - Protected flow stages are server-authoritative via `/api/recovery-status`.
  - Users cannot directly navigate to later stages without satisfying earlier stages.

- **PASS — MFA simulation**
  - The flow includes MFA after reset-token verification.
  - The deterministic mock MFA code is shown in the UI and logged in the browser console.
  - MFA verification is server-enforced before password reset is permitted.

- **PASS — Password policy and storage**
  - Passwords require at least 12 characters, uppercase, lowercase, number, and symbol.
  - Passwords are limited to 72 UTF-8 bytes, appropriate for bcrypt.
  - Passwords are hashed with `Bun.password.hash(..., { algorithm: "bcrypt", cost: 12 })`.
  - Plaintext passwords are not stored, rendered, or logged after submission.

- **PASS — Brute-force mitigation**
  - Recovery initiation is throttled per session and client/IP bucket.
  - Token, MFA, and password failures are rate-limited per client/IP.
  - Per-recovery failed-attempt counters block repeated attempts for one minute after the configured limit.

- **PASS — XSS and injection protections**
  - User-controlled dynamic values are inserted with `textContent`, not `innerHTML`.
  - Token values are validated before use.
  - Passwords and email values are never rendered back into the document.
  - CSP nonce protection is used for the intentionally embedded trusted style and script blocks.

- **PASS — Security headers**
  - Responses include CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, and no-store cache headers.
  - CSP restricts scripts and styles to the server-generated nonce and limits connections to same origin.

- **PASS — No sensitive data exposure**
  - The application does not expose patient records, usernames, account identifiers, course folders, or other private account data.
  - Error handling is generic and does not expose stack traces or debugging output.

- **PASS — Phishing and safe-authentication guidance**
  - Each recovery stage includes clear guidance not to share passwords, recovery tokens, or MFA codes.
  - The UI advises users to access the hospital through a trusted address/bookmark and avoid unexpected links.

- **PASS — Semantic and usable UI**
  - The artifact uses semantic elements including `header`, `main`, `footer`, `section`, `form`, `label`, headings, and lists.
  - Fields have associated labels, buttons have clear actions, notices communicate success/error state, and the activity log has accessible live-region semantics.

## FAILING_ITEMS

- None identified.

## NEW_TASKS

1. None required.

## DECISION

PASS