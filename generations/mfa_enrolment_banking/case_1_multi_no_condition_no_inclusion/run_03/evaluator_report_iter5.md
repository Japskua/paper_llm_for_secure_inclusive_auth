## SUMMARY

The artifact is a single-file Bun HTTPS MFA enrolment application with a responsive mobile UI, server-side sessions, CSRF checks, authorization derived from an HttpOnly cookie, encrypted TOTP secret storage, PBKDF2 recovery-code verifiers, rate limiting, and browser-only test fixtures. However, it does not fully meet the requirements because the TOTP implementation can generate invalid negative OTP strings for approximately half of provisioning attempts, making authenticator confirmation unreliable. Its CSP also permits arbitrary inline script execution via `'unsafe-inline'`, which is not a sufficiently secure CSP for the stated XSS/security-misconfiguration requirements.

## FUNCTIONAL_CHECK

- **PASS — Single-file application and zero-build operation:**  
  The complete Bun server, HTML, CSS, and browser JavaScript are contained in `app.ts`. It uses `Bun.serve` directly and does not use frameworks, bundlers, external assets, or external network calls.

- **PASS — HTTPS/TLS use:**  
  The Bun server is configured with `certs/cert.pem` and `certs/key.pem`, and the session cookie is marked `Secure`. The application only exposes the TLS server configuration.

- **PASS — Mobile-responsive and legible UI:**  
  The UI uses a constrained mobile-width shell, responsive font sizing, accessible form labels, touch-sized controls, and a narrow-screen media query.

- **PASS — MFA flow and internal UI navigation:**  
  The client supports sign-in, identity-code verification, authenticator provisioning, authenticator confirmation, recovery-code display/download/acknowledgement, regeneration, recovery-code verification, and logout. State transitions work through client-side rendering.

- **FAIL — Authenticator OTP verification reliably works:**  
  `totpForSecret()` constructs the dynamic-truncation result with signed JavaScript bitwise operators:
  ```ts
  const value = ((hmac[offset] & 127) << 24) | ...
  ```
  JavaScript bitwise results are signed 32-bit integers. When bit 31 is set after shifting, `value` becomes negative. Then:
  ```ts
  String(value % 1_000_000).padStart(6, "0")
  ```
  can produce values such as `-12345`, which do not match the required `/^\d{6}$/` server validation or the client-side numeric input pattern. As a result, a substantial portion of generated TOTP fixtures cannot be submitted successfully.

- **PASS — Manual test values are shown and logged in the browser:**  
  In explicit test mode, the identity code, manual authenticator secret, TOTP fixture, and recovery codes are displayed in the UI and sent to `console.log` in browser JavaScript. The server does not log these values.

- **PASS — Server-side authorization and IDOR protection:**  
  MFA endpoints derive the user exclusively from the opaque `mfa_session` cookie. No client-supplied account/user identifier is accepted by MFA endpoints, preventing manipulated user-ID access.

- **PASS — CSRF protection for state-changing authenticated MFA requests:**  
  MFA provisioning, confirmation, recovery regeneration, recovery verification, acknowledgement, and logout require an anti-CSRF token. Requests also reject untrusted `Origin` values, and cookies use `SameSite=Strict`.

- **PASS — Session security:**  
  Session cookies use `HttpOnly`, `Secure`, and `SameSite=Strict`. Sessions have idle and absolute timeouts. The session ID is rotated after successful identity verification, and logout invalidates the session and expires the cookie.

- **PASS — Rate limiting, lockout, and one-time verification behavior:**  
  Identity verification, authenticator confirmation, and recovery-code verification enforce failure counters and lockouts. Identity codes are marked used after success, pending authenticator setup is time-bound, and successful recovery codes are consumed.

- **PASS — Secret storage protections:**  
  Pending TOTP secrets are AES-GCM encrypted before storage. Recovery codes are not retained in plaintext and are stored as salted PBKDF2-SHA-256 verifiers. Random secrets, tokens, IVs, salts, and recovery codes use `crypto.getRandomValues`.

- **PASS — Input validation and redirect restrictions:**  
  JSON bodies are constrained to allow-listed fields. Email, phone, OTP, identity code, and recovery-code formats are validated server-side. The only accepted `redirect` value is `/`, and the application does not issue user-controlled redirects.

- **FAIL — Secure CSP/XSS hardening is insufficient:**  
  The CSP contains:
  ```http
  script-src 'unsafe-inline'
  style-src 'unsafe-inline'
  ```
  In particular, `script-src 'unsafe-inline'` allows arbitrary inline scripts if an HTML injection vulnerability is introduced. This weakens CSP substantially and does not meet the requirement for a secure CSP intended to mitigate XSS. A nonce- or hash-based CSP should be used for the static inline script.

- **PASS — Other required security headers and restricted CORS:**  
  Responses include HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, and `Permissions-Policy`. CORS headers are only emitted for trusted local HTTPS origins.

- **PASS — Generic error handling and no server-side sensitive logging:**  
  The request handler catches errors and returns generic failures. Sensitive values are not placed in URLs, server error output, or server logs. Browser fixture logging is explicitly required by the test-mode deliverable.

## FAILING_ITEMS

- **TOTP generation uses signed bitwise arithmetic and can return invalid negative OTP values.**  
  This breaks authenticator enrolment for generated fixtures where the truncated HMAC value is interpreted as a negative signed 32-bit integer.

- **The CSP allows `'unsafe-inline'` scripts.**  
  This is not a sufficiently restrictive CSP for the security requirement and weakens defense against script injection.

## NEW_TASKS

1. Update `totpForSecret()` to convert the dynamic-truncation value to an unsigned 32-bit integer before modulo calculation, for example by applying `>>> 0` to the combined bitwise value; ensure it always returns exactly six ASCII digits.

2. Replace `script-src 'unsafe-inline'` with a nonce- or SHA-256 hash-based CSP policy for the static inline client script. Apply the same nonce/hash mechanism to inline styles as appropriate, while preserving direct single-file Bun operation.

## DECISION

**FAIL**