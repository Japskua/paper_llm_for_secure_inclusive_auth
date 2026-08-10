## SUMMARY

The artifact is a strong single-file Bun implementation with TLS, session-based authorization, CSRF controls, secure headers, responsive mobile UI, accessible dyslexia-aware styling, and working simulated identity, TOTP, and recovery-code flows. However, the custom QR generator does not generate a valid standards-compliant QR Code Version 10 matrix because it omits and fails to reserve the required version-information areas. As a result, the advertised QR setup option cannot be relied upon to scan correctly, so the artifact does not fully meet the provisioning requirements.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no framework, bundler, compiler, or external assets.**  
  The server, HTML, CSS, and vanilla client JavaScript are all contained in `app.ts`. It uses `Bun.serve`, inline template content, and no external network assets or build tooling.

- **PASS — TLS is configured using the required certificate paths.**  
  The app reads `certs/cert.pem` and `certs/key.pem` and supplies both via Bun’s `tls: { cert, key }` configuration.

- **PASS — Mobile-responsive and dyslexia-aware UX is substantially implemented.**  
  The layout is constrained for mobile widths, uses large controls, substantial line/letter spacing, clear visual hierarchy, plain-language text, icons paired with labels, prominent step indicators, and visible examples for expected input.

- **PASS — Identity-verification flow is simulated and functional.**  
  A six-digit code is securely generated, returned only to the authenticated browser UI for the stated mock/testing flow, logged in the browser console, is single-use, expires after 15 minutes, and is rate-limited after repeated invalid submissions.

- **PASS — Authenticator provisioning and TOTP verification are implemented.**  
  The application generates a cryptographically random Base32 secret, encrypts it in server memory with AES-GCM, generates TOTP values using HMAC-SHA-1, accepts a small clock window, and prevents reuse of an accepted TOTP time step.

- **FAIL — QR-code provisioning option is not standards-compliant or reliably scannable.**  
  The `qrCanvas()` function creates a Version 10 (`N = 57`) QR matrix but does not write or reserve the mandatory Version Information modules required for QR versions 7 and above. Those locations are instead populated as data modules. A conforming QR scanner will interpret those cells as version information, corrupting the data stream and potentially rejecting the QR code. Therefore, the offered QR option cannot be considered functional.

- **PASS — Manual authenticator setup is supported.**  
  The setup secret can be revealed, copied to the clipboard, copied as an `otpauth://` URI, and pasted manually into the optional manual setup-key field. The secret is not placed in URL query navigation or browser storage.

- **PASS — Recovery-code generation, display, copying, regeneration, and one-time use are implemented.**  
  Eight recovery codes are cryptographically generated, stored server-side only as salted hashes, shown only when requested, copyable, regenerable, and invalidated after use. Recovery-code attempts are rate-limited and temporarily locked after repeated failure.

- **PASS — Server-side authorization prevents IDOR.**  
  Account identity is derived solely from the HttpOnly session cookie. Client-controlled account IDs are not accepted by MFA endpoints, and all authenticated routes resolve the account only from the server-side session.

- **PASS — State-changing authenticated MFA requests use CSRF protection.**  
  The application creates an anti-CSRF token for a session and validates it on authenticated POST routes. Session cookies also use `SameSite=Strict`.

- **PASS — Secure session cookie flags and session lifetime controls are present.**  
  Session cookies include `HttpOnly`, `Secure`, and `SameSite=Strict`. Sessions enforce idle and absolute expiration, are regenerated on successful sign-in, and are removed on logout.

- **PASS — Required security headers are configured.**  
  Responses include CSP with nonce-based inline script/style authorization, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, restrictive referrer policy, permissions policy, and `Cache-Control: no-store`.

- **PASS — CORS is restricted to trusted local TLS origins.**  
  CORS headers are returned only for the configured localhost, IPv4 localhost, or IPv6 localhost HTTPS origins.

- **PASS — Inputs are server-side validated and client rendering avoids obvious XSS sinks.**  
  JSON bodies are size-limited and parsed safely; expected values are validated with constrained formats; client values are rendered through `textContent` and DOM APIs rather than unsafe `innerHTML`.

- **PASS — Generic server errors are returned without stack traces.**  
  The top-level handler catches unexpected errors and returns a generic error message.

- **PASS — No secrets or session tokens are persisted in browser storage.**  
  The code does not use `localStorage`, `sessionStorage`, IndexedDB, or non-HttpOnly cookies for OTP secrets, recovery codes, or sessions.

## FAILING_ITEMS

- **The QR generator is invalid for the selected QR version.**  
  `qrCanvas()` uses a Version 10 matrix (`57 × 57`) but does not implement Version Information BCH data and does not reserve the two Version Information regions. For Version 10, these regions are mandatory:
  - top-right: rows `0..5`, columns `N-11..N-9`
  - bottom-left: rows `N-11..N-9`, columns `0..5`

  Because these modules are left unreserved, data bits are written into them. This makes the matrix structurally non-compliant and may prevent authenticator apps from scanning the `otpauth://` URI.

## NEW_TASKS

1. **Fix the QR encoder to produce a standards-compliant QR Version 10-L code.**  
   Reserve both Version Information regions before data placement, calculate the Version 10 BCH version-information value according to ISO/IEC 18004, and write the 18 version-information bits to both required locations.

2. **Validate the corrected QR output with a standards-compliant QR decoder.**  
   Confirm that a generated provisioning URI can be scanned successfully by at least one independent QR decoder and that the decoded value exactly matches the expected `otpauth://totp/...` URI.

## DECISION

FAIL