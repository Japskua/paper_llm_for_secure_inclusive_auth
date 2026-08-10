## SUMMARY

The artifact is a well-structured single-file Bun HTTPS SPA with strong coverage of the enrolment flow, mobile accessibility, session ownership, CSRF checks, security headers, encrypted TOTP-secret storage, hashed recovery codes, rate limiting, and browser-console mock output. However, the offered QR-code provisioning path is technically invalid because its QR Reed–Solomon block layout does not match the QR Version 10-L specification. This makes the QR option unreliable/unscannable, so the artifact cannot be accepted as fully functional.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no framework, bundler, compiler, or external assets**
  - The server, HTML, CSS, and browser JavaScript are all contained in `app.ts`.
  - It uses `Bun.serve` directly and references only the locally supplied TLS certificate files.

- **PASS — HTTPS/TLS server configuration**
  - Bun is configured with `certs/cert.pem` and `certs/key.pem`.
  - Non-HTTPS requests are rejected by the handler, and HSTS is returned.

- **PASS — Responsive and mobile-oriented MFA enrolment UI**
  - The document includes a mobile viewport declaration, constrained mobile layout, readable controls, responsive recovery-code grid, sufficient touch target sizing, and generous spacing.

- **PASS — Dyslexia-aware UX**
  - The UI uses a legible sans-serif font, increased letter/line spacing, short instructions, examples for expected formats, visible current-step progress, clear feedback, no timers/animation, help disclosures, retry routes, copy controls, and hide/reveal functionality.
  - OTP input supports `autocomplete="one-time-code"` and numeric mobile keyboards.

- **PASS — Functional sign-in and session creation**
  - Demo credentials are provided and accepted.
  - Session IDs are generated with cryptographic randomness, existing sessions for the user are removed on login, and session cookies use `HttpOnly`, `Secure`, and `SameSite=Strict`.

- **PASS — Server-side authorization and IDOR protection**
  - MFA API routes derive the account exclusively from the server-side session.
  - No route accepts a client-controlled user/account identifier, preventing guessed or manipulated-ID access.

- **PASS — CSRF protection for state-changing authenticated requests**
  - Authenticated POST operations require both a same-origin HTTPS request and the session-bound `X-CSRF-Token`.
  - State-changing operations including provisioning, verification, recovery-code regeneration, reenrolment, and logout are covered.

- **PASS — Security misconfiguration controls**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, restrictive `Permissions-Policy`, and `Cache-Control: no-store` are set.
  - CORS only permits the matching trusted local origin with credentials.

- **PASS — TOTP provisioning, manual-secret entry, and verification**
  - A cryptographically generated Base32 secret is supplied as a manual secret and in an `otpauth://` URI.
  - TOTP is implemented using HMAC-SHA-1, 30-second periods, six digits, a bounded clock skew, and replay prevention through used moving-factor tracking.
  - The mock verification OTP is returned to the browser and written to the browser console as required.

- **FAIL — QR-code provisioning option functions correctly**
  - The custom QR encoder claims Version 10-L but splits its 274 data codewords into blocks sized `68, 69, 69, 68`.
  - QR Version 10-L requires two 68-byte data blocks followed by two 69-byte data blocks: `68, 68, 69, 69`.
  - Because the encoder interleaves data using the wrong block allocation, a normal QR decoder deinterleaves the final bytes into the wrong error-correction blocks. The resulting symbol is not standards-compliant and may not scan.
  - This violates the requirement that a QR provisioning option, when offered, must work.

- **PASS — Recovery-code generation and handling**
  - Ten cryptographically random recovery codes are generated.
  - Only keyed hashes are stored server-side.
  - Codes can be copied, hidden/revealed, regenerated, and consumed once.

- **PASS — Verification attempt limiting and lockout**
  - OTP and recovery-code verification have separate failure counters, a five-attempt threshold, and a five-minute lockout.
  - Messages clearly state the problem and corrective action.

- **PASS — Secret handling and browser-storage restrictions**
  - The application does not use `localStorage`, `sessionStorage`, URL query parameters, or non-HttpOnly cookies for session tokens or MFA material.
  - TOTP secrets are AES-GCM encrypted in server memory; recovery codes are stored only as keyed hashes.
  - Sensitive mock values are logged only by browser-side `console.log`, as explicitly required for testing.

- **PASS — Error handling and output encoding**
  - Generic server error responses are returned instead of stack traces.
  - User-visible dynamic values inserted through HTML are escaped where applicable.
  - There are no user-controlled redirects or external network calls.

## FAILING_ITEMS

- **The QR encoder is not standards-compliant for Version 10-L.**
  - The Reed–Solomon data block partitioning is incorrectly implemented as `68, 69, 69, 68`.
  - The required Version 10-L partition is `68, 68, 69, 69`.
  - As a result, the QR provisioning image can fail to scan, despite being presented as a supported setup method.

## NEW_TASKS

1. Correct the inline QR encoder’s Version 10-L Reed–Solomon block partitioning and interleaving to use two 68-data-codeword blocks followed by two 69-data-codeword blocks (`68, 68, 69, 69`), then verify that the generated `otpauth://` URI scans successfully in a standard authenticator/QR scanner.

## DECISION

**FAIL**