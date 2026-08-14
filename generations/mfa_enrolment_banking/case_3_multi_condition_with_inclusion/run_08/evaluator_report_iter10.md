## SUMMARY

The artifact is a well-structured single-file Bun application with a responsive mobile MFA flow, server-side session ownership checks, CSRF protection, TLS configuration, restrictive security headers, encrypted TOTP-secret storage, hashed recovery codes, and usable simulated verification flows. However, the self-contained QR encoder produces an invalid Version 10 QR payload because it encodes the byte-mode character count using 8 bits instead of the required 16 bits. As a result, the displayed provisioning QR code is not standards-compliant/scannable, so the QR provisioning requirement is not functionally met.

## FUNCTIONAL_CHECK

- **Single `app.ts` Bun server containing HTML, CSS, and vanilla browser JavaScript — PASS**
  - The full application, including Bun server, API logic, generated HTML, inline CSS, and inline client-side JavaScript, is contained in one file.
  - It uses no framework, bundler, compiler command, external asset, or external network call.

- **TLS/HTTPS service using supplied `certs/cert.pem` and `certs/key.pem` — PASS**
  - The server loads the specified certificate files and starts `Bun.serve` with a TLS configuration.
  - HSTS is included in response headers.
  - Requests marked as forwarded over HTTP are rejected.

- **Responsive, legible mobile UI with dyslexia-inclusive UX — PASS**
  - The layout is constrained to a mobile-friendly maximum width and includes a small-screen media query.
  - The selected font stack is legible, with increased line height and letter spacing.
  - Instructions are short, use plain language, provide examples, include icons, and avoid time-pressure messaging.
  - The application includes clear primary actions, help controls, retry/re-request controls, success messages, and specific error messages.

- **Identity-code simulation and verification — PASS**
  - Identity codes are generated server-side, are time-bound, single-use, tied to the authenticated session, and are validated server-side.
  - Failed attempts are counted and lock out after repeated failures.
  - The simulated identity code is returned to the browser and logged via browser `console.log`.

- **Authenticator provisioning, manual setup key, and authenticator-code verification — PASS, except QR validity**
  - The server securely generates a random Base32 TOTP secret.
  - The secret is encrypted at rest with AES-GCM.
  - A grouped manual setup key is shown, can be hidden/revealed, and can be copied to the clipboard.
  - The provisioning URI can be copied.
  - TOTP verification is server-side, accepts a limited clock window, prevents reuse of accepted time steps, and locks out repeated failures.
  - The simulated TOTP is returned to browser code and written to browser `console.log`.
  - **The QR portion of this criterion fails because the generated QR code is malformed; see below.**

- **QR-code provisioning option works — FAIL**
  - The UI renders an SVG intended to be a QR code, but `qrMatrix()` declares a Version 10 QR code and encodes byte-mode character count with `add(bytes.length, 8)`.
  - QR Code byte-mode character count fields require **16 bits for Versions 10–40**. Version 10 is explicitly used (`N=57`, version information for 10).
  - A scanner will interpret the first eight bits of URI data as part of the length field, resulting in an invalid/impossible payload length. The QR code therefore cannot reliably be scanned/imported by authenticator applications.

- **Recovery-code generation, display, copy, and one-time verification — PASS**
  - Eight recovery codes are generated with cryptographically secure randomness.
  - Codes are only stored as salted hashes server-side.
  - Codes are returned to the protected UI and logged to the browser console for the specified test mock behavior.
  - Codes can be hidden/revealed and copied.
  - Verification is server-side, rejects invalid formats, prevents reuse, and locks out repeated failures.

- **Server-side authorization and IDOR prevention — PASS**
  - MFA API endpoints obtain the account exclusively through the authenticated server-side session.
  - Client-controlled account/user identifiers are rejected by `safeObject`.
  - There are no API routes that accept an arbitrary account identifier to read or alter MFA state.

- **CSRF protection for state-changing operations — PASS**
  - Authenticated state-changing endpoints require a per-session CSRF token through `X-CSRF-Token`.
  - Sign-in has a separate bootstrap CSRF mechanism using a SameSite cookie and request token.
  - Logout, identity-code request/verification, provisioning, authenticator confirmation, recovery generation, and recovery verification are protected.

- **Secure headers, CORS, cookies, and error handling — PASS**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, referrer policy, and no-store cache controls are present.
  - CORS is restricted to an explicit local trusted-origin allow-list.
  - The authenticated session cookie is `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - Generic server error responses avoid exposing stack traces or secrets.

- **No sensitive values persisted in browser storage or URLs — PASS**
  - The application does not use `localStorage` or `sessionStorage`.
  - Session IDs are held in HttpOnly cookies rather than browser JavaScript or URLs.
  - Secrets/codes are not placed in query strings.
  - Sensitive mock values are not written to the visible activity-log panel.

- **Input validation and XSS/open-redirect protections — PASS**
  - Email, password, OTP, and recovery-code inputs are server-side validated.
  - Untrusted values are not interpolated unsafely into the page; dynamic secret/code rendering uses `textContent`.
  - The hash router is restricted to a fixed allow-list and no server-side redirect parameter is accepted.

- **Internal navigation and completion flow — PASS**
  - Hash routes are allow-listed and route guards prevent skipping required identity/MFA steps.
  - Links/buttons for setup, confirmation, recovery-code viewing, recovery-code testing, logout, retry, and completion are implemented.

## FAILING_ITEMS

- **The provisioning QR code is not standards-compliant and may not scan.**
  - In `qrMatrix(text)`, the code creates a Version 10 QR code but writes the byte-mode character count using:
    ```js
    add(bytes.length, 8);
    ```
  - For QR Versions 10 through 40, byte-mode character counts are required to use 16 bits.
  - This corrupts the encoded payload length and means authenticator applications cannot reliably parse the `otpauth://` URI from the displayed QR image.

## NEW_TASKS

1. Update the QR byte-mode encoder in `qrMatrix()` so that Version 10 uses a 16-bit byte-mode character-count field:
   ```js
   add(bytes.length, 16);
   ```
   Ensure the terminator and padding calculations remain based on the resulting bit length.

2. Validate the generated SVG QR output using a standards-compliant QR scanner or automated QR decoding test against a generated `otpauth://totp/...` URI, confirming that the decoded URI exactly matches `provision.provisioningUri`.

## DECISION

**FAIL**