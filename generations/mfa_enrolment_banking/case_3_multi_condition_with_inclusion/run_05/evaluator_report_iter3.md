## SUMMARY

The artifact is a strong single-file Bun HTTPS MFA demo with responsive mobile UI, server-side sessions, CSRF checks, encrypted TOTP secrets, hashed recovery codes, rate limiting, and browser-side mock delivery logs. However, it does not fully satisfy the requirements because the generated QR code is not reliably standards-compliant: version-information modules are written after data placement rather than reserved before placement, and the rendered QR code lacks the required four-module quiet zone. This can prevent the promised authenticator QR provisioning path from working reliably.

## FUNCTIONAL_CHECK

- **Single-file Bun application with inline HTML, CSS, and vanilla JavaScript — PASS**
  - The supplied artifact is one `app.ts` file containing the Bun server, HTML template, CSS, and browser JavaScript.
  - No framework, bundler, compiler step, or external web asset is used.

- **HTTPS/TLS server using supplied mkcert certificate paths — PASS**
  - `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`.
  - The application is intended to run over HTTPS and applies HSTS.

- **Responsive, legible mobile MFA enrolment UI — PASS**
  - The UI uses a narrow mobile shell (`width:min(100%,560px)`), large controls, adequate spacing, visible focus styling, plain-language content, examples, and predictable five-step progression.
  - Inputs use relevant `autocomplete`, `inputmode`, and password-manager-compatible attributes where appropriate.

- **Dyslexia-inclusive UX — PASS**
  - Instructions are short and plain.
  - The UI uses generous spacing, readable sizing, simple step labels, icons, help disclosures, visible primary actions, copy controls, and no timers or moving content.
  - Error messages explain the issue and how to fix it.

- **Identity-code delivery and verification simulation — PASS**
  - A mock identity code is returned to the client and displayed in the browser-side test log via `console.log`.
  - The code is time-bound, single-use after successful verification, and rate-limited after failed attempts.
  - Re-requesting an identity code is supported.

- **TOTP provisioning and manual setup-secret submission — PARTIAL / FAIL**
  - The server securely generates a TOTP secret, encrypts it at rest in the session, returns an `otpauth://` URI, and allows the displayed secret to be copied and manually submitted.
  - However, the QR rendering implementation is faulty/non-compliant, so the QR provisioning option cannot be accepted as reliably functional.

- **TOTP verification — PASS**
  - The implementation derives RFC-style six-digit TOTP values using HMAC-SHA-1 and 30-second time steps.
  - It accepts a limited clock-skew window, prevents reuse of a successfully accepted TOTP time step, and rate-limits failures.
  - The mock OTP is returned to the UI and logged in the browser console for testing.

- **Backup recovery-code display, copy, hide/reveal, and confirmation — PASS**
  - Eight cryptographically generated recovery codes are returned after TOTP verification, shown in the UI, copied to clipboard, and logged in the browser console as requested for testing.
  - Codes can be hidden/revealed.
  - Confirmation validates a pasted code without consuming it, matching the screen wording.

- **Server-side authorization and IDOR prevention — PASS**
  - MFA state is tied to the authenticated server-side session.
  - The server does not accept client-provided account identifiers and rejects `userId`/`accountId` fields.
  - MFA endpoints require an authenticated account-owning session.

- **CSRF protection for state-changing endpoints — PASS**
  - State-changing API calls require a session-bound CSRF token.
  - Session cookies use `SameSite=Strict`, further reducing cross-site request risk.

- **Secure session handling — PASS**
  - Session IDs are securely generated, rotated upon sign-in, stored in `HttpOnly; Secure; SameSite=Strict` cookies, subject to idle and absolute expiry, and invalidated on logout.

- **Secure headers and restrictive CORS — PASS**
  - CSP with per-response nonce, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, referrer policy, permissions policy, and no-store caching are configured.
  - CORS is restricted to explicit local HTTPS origins.

- **Secret storage and cryptographic protection — PASS**
  - TOTP secrets are AES-GCM encrypted in server memory.
  - Recovery codes use random salts and PBKDF2-SHA-256 with 210,000 iterations.
  - Secrets and codes are not stored in browser storage or non-HttpOnly cookies.

- **Input validation and XSS controls — PASS**
  - Server-side validation exists for email, password, identity code, TOTP code, recovery code, and manual secret.
  - Client-rendered variable content is escaped before insertion into `innerHTML`.
  - Redirect input is rejected and no user-controlled redirect target is used.

- **Generic production error handling — PASS**
  - The server catches unhandled failures and returns a generic message rather than a stack trace.

## FAILING_ITEMS

- **QR code generation is not standards-compliant and may not scan reliably.**
  - In `drawQR`, version-information modules are written only after the QR data stream has already been placed:
    - Data placement occurs in the `for(let c=N-1; ...)` loop.
    - Version bits are then written afterward with `set(...)` calls for the version-information regions.
  - Those version-information regions must be reserved before data placement. Writing them afterward overwrites encoded data modules.
  - Although Reed-Solomon correction may sometimes mask this defect, the QR symbol is not correctly constructed and cannot be treated as a reliable provisioning mechanism.

- **The QR canvas does not include the required quiet zone.**
  - A QR code needs a white margin of at least four modules on all sides.
  - The rendered symbol contains only the 49×49 module matrix. The CSS padding around it is 10 CSS pixels, which is substantially less than four modules at the rendered module size.
  - This further reduces scan reliability, especially on mobile screens and lower-quality cameras.

- **The QR implementation’s claim of being “Standards-compliant QR version 8-L” is inaccurate.**
  - The comment states that the encoder is standards-compliant, but the missing reservation of version-information regions and insufficient quiet zone mean it does not meet that claim.

## NEW_TASKS

1. Update `drawQR` so that both version-information regions are marked as reserved in the module matrix before QR data-bit placement begins.

2. Place QR version information only into already reserved version-information modules after data placement, ensuring no encoded data modules are overwritten.

3. Render a true four-module quiet zone around the QR symbol, either by:
   - increasing the canvas matrix to include four white modules on every side, or
   - rendering the QR modules at a known integer scale and adding white canvas padding equal to at least four rendered modules.

4. Validate the generated `otpauth://` QR code with a standard QR scanner/authenticator application and confirm that it provisions the same secret shown in the manual setup field.

5. Remove or revise the “Standards-compliant QR version 8-L” comment unless the repaired implementation is verified against a compliant QR encoder/scanner.

## DECISION

FAIL