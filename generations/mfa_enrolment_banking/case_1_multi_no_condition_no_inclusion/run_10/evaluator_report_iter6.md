## SUMMARY

The artifact is a valid single-file Bun HTTPS MFA enrolment SPA. It provides a mobile-responsive vanilla HTML/CSS/JS UI, server-side session ownership checks, CSRF validation, TLS, security headers, encrypted OTP-secret storage, hashed recovery codes, rate limiting, session rotation, and functional mock enrolment/recovery flows. Mock OTP and recovery values are intentionally surfaced only through the browser UI/console as explicitly required for evaluation.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no frameworks, bundlers, compilation, or external network calls.**  
  The complete server, HTML, CSS, and client-side JavaScript are contained in `app.ts`. It uses `Bun.serve`, inline template content, native browser APIs, and no external assets or requests.

- **PASS — HTTPS/TLS is configured with the required certificate locations.**  
  `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`. HSTS is also sent in response headers.

- **PASS — Mobile-responsive and legible SPA UI.**  
  The document includes a viewport meta tag, a constrained mobile-friendly content width, responsive spacing, accessible labels, semantic sections/forms, and touch-sized buttons.

- **PASS — Sign-in and identity-verification flow works.**  
  The sign-in endpoint validates email and phone inputs, creates a time-limited challenge, rotates the session, and returns the simulated identity OTP for browser-console/UI evaluation. Identity verification validates the OTP and advances only the verified account session.

- **PASS — Authenticator provisioning and manual entry work.**  
  The application provides a manual setup secret and provisioning URI. The secret can be manually submitted along with the deterministic server-generated authenticator OTP. Provisioning and confirmation endpoints enforce state, CSRF, validation, and ownership.

- **PASS — Recovery-code enrolment and regeneration flow works.**  
  Eight cryptographically generated recovery codes are created, displayed only once, hashed server-side, individually consumed on use, and required before regeneration. Regeneration requires a short-lived recovery verification grant.

- **PASS — Browser mock logging requirement is met.**  
  Identity OTPs, authenticator test OTPs, and recovery codes are logged through browser-side `console.log` and displayed in the evaluation Logs panel. The server itself does not log secrets.

- **PASS — Server-side authorization and IDOR protections are implemented.**  
  MFA settings, provisioning, authenticator confirmation, recovery verification, recovery-code access, regeneration, and logout all resolve state from the authenticated server-side session rather than accepting a user identifier from the client. Account access is not determined from a manipulable endpoint identifier.

- **PASS — CSRF protection is applied to state-changing requests.**  
  A cryptographically random CSRF token is associated with each server session. All POST state-changing API endpoints require a matching token. Session cookies also use `SameSite=Strict`.

- **PASS — Secure session cookie configuration is present.**  
  Session cookies use `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, and bounded `Max-Age`. Logout expires the session cookie, and server-side session state is deleted.

- **PASS — Session fixation and expiry controls are implemented.**  
  Sessions rotate after sign-in and identity verification. Server-side sessions have both idle and absolute timeouts. Logout invalidates the server-side session.

- **PASS — Required security headers are set.**  
  Responses include CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, CSP `frame-ancestors 'none'`, `Referrer-Policy`, and `Permissions-Policy`.

- **PASS — CSP is compatible with the inline single-file design.**  
  The HTML response generates a fresh nonce and applies it to both inline CSS and inline JavaScript. CSP does not rely on `unsafe-inline`.

- **PASS — CORS is restricted to trusted local HTTPS origins.**  
  Trusted origins are explicitly limited to `https://localhost:<port>`, `https://127.0.0.1:<port>`, and `https://[::1]:<port>`. Other origins are rejected.

- **PASS — OTP secret and recovery-code storage are protected.**  
  Authenticator secrets are generated using cryptographic randomness and encrypted with AES-GCM before being retained in server state. Recovery codes are generated with cryptographic randomness and stored as SHA-256 hashes with a server-held pepper.

- **PASS — No browser storage or client-readable session cookie is used for secrets/tokens.**  
  The code does not use `localStorage`, `sessionStorage`, IndexedDB, or non-HttpOnly cookies for session tokens, OTP secrets, or recovery codes.

- **PASS — Server-side input validation is implemented.**  
  Email, phone, OTP, manual authenticator secret, and recovery-code inputs are validated using strict server-side type, length, and format checks before use.

- **PASS — XSS/output-handling controls are adequate for this UI.**  
  The UI renders dynamic values through `textContent` and DOM node creation rather than `innerHTML`. Server responses are JSON and the HTML page has no reflection of raw request values.

- **PASS — Error output is generic and does not expose stack traces or sensitive internals.**  
  API failures return generic messages. The outer request handler catches unexpected failures and emits a generic response without verbose details.

- **PASS — Verification values are time-bound, single-use where applicable, and rate-limited.**  
  Identity challenges expire and are marked used after success. Authenticator enrolment confirmation can only succeed once. Recovery codes are deleted after successful use. Identity, authenticator, and recovery verification attempts are locked after repeated failures.

- **PASS — No open redirect capability exists.**  
  The application contains no client-controlled redirect endpoint or redirect parameter handling.

## FAILING_ITEMS

- None.

## NEW_TASKS

1. No remediation tasks are required.

## DECISION

PASS