## SUMMARY

The artifact is a single-file Bun HTTPS SPA with a strong overall structure, responsive mobile UI, browser-side mock logging, CSRF/session handling, encrypted OTP-secret storage, hashed recovery codes, and restrictive security headers. However, it does not fully meet the requirements because real TOTP values are replayable rather than single-use, the offered QR-code generator is defective, and the recovery-success screen presents more than one primary action.

## FUNCTIONAL_CHECK

- **Single `app.ts` file containing Bun server, HTML, CSS, and vanilla browser JavaScript: PASS**
  - The entire server and SPA template are in one file. No framework, bundler, external asset, or external network request is used.

- **Bun HTTPS server uses the required local TLS certificate paths: PASS**
  - `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`.
  - The server listens over HTTPS and prints an HTTPS localhost URL.

- **Mobile-responsive, legible, dyslexia-aware UI: PASS**
  - The layout is constrained for mobile widths, uses generous spacing, readable font sizing, visible focus states, clear step indicators, short plain-language instructions, examples, icons, and non-moving content.
  - Inputs include suitable `autocomplete`, `inputmode`, and one-time-code hints.

- **Clear, navigable MFA enrolment flow: PASS**
  - The SPA supports sign-in, identity confirmation, authenticator setup, TOTP confirmation, backup-code generation, recovery-code checking, completion, back navigation, help, hiding/revealing sensitive values, and logout.
  - There are no broken internal hyperlink targets; SPA navigation is handled through working button actions.

- **Manual and copy-based authenticator setup support: PASS**
  - The provisioning URI and manual Base32 key are shown to the authenticated user and can be copied.
  - The manual key permits setup in an authenticator without manually transcribing the URI or QR content.

- **Browser-side mock handling and console logging: PASS**
  - The explicit mock OTP is returned to the authenticated UI and logged via browser `console.log`.
  - Generated backup recovery codes are returned to the UI and logged via browser `console.log`.
  - Sensitive mock values are not logged by the server.

- **Backup codes are securely generated and stored: PASS**
  - Recovery codes are generated from `crypto.getRandomValues`.
  - Only SHA-256 hashes with a server-side pepper are retained in application state.
  - Used recovery-code hashes are deleted, making recovery codes single-use.

- **OTP secret storage is protected at rest: PASS**
  - The OTP secret is encrypted using AES-GCM before storage in the MFA record.
  - The encryption key is non-extractable and generated server-side using cryptographically secure randomness.

- **Real TOTP verification works, including an allowed clock window: PASS**
  - RFC-6238-style HMAC-SHA-1 TOTP validation is implemented with a 30-second step and a ±1 step clock window.
  - Six-digit TOTP format validation is present.

- **Verification codes/OTPs are single-use: FAIL**
  - `/api/otp` validates a TOTP but never rejects a code that was previously accepted.
  - `state.otpUsed` is set by `completeOtp`, but it is not checked in `/api/otp`.
  - Therefore, the same valid TOTP can be submitted repeatedly during its valid time window, violating the explicit single-use requirement.

- **Mock verification code is single-use and time-bound: PASS**
  - The mock flow uses `mockUsed`, `mockExpires`, a setup session, and a replaceable challenge.
  - Re-requesting invalidates the old mock code.

- **Failed verification attempts are rate-limited and locked out: PASS**
  - Validly formatted but incorrect OTP and recovery-code entries increment a failure counter.
  - Five failures cause a five-minute lockout.

- **Server-side account ownership and IDOR protections: PASS**
  - Authenticated API routes derive account identity from the server-side session.
  - Account identifiers supplied by clients are explicitly rejected.
  - All MFA state is resolved against the authenticated fixed account, not a user-controlled identifier.

- **CSRF protections on state-changing requests: PASS**
  - State-changing endpoints require both a same-origin HTTPS `Origin` check and a per-session CSRF token.
  - The session cookie uses `SameSite=Strict`.

- **Secure session-cookie handling and session expiry: PASS**
  - The session cookie is `HttpOnly`, `Secure`, `SameSite=Strict`, path-scoped, and has a bounded lifetime.
  - Server-side idle and absolute session timeouts are enforced.
  - Logout deletes the session and expires the cookie.

- **Required security headers and CORS restriction: PASS**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, referrer policy, permissions policy, and no-store cache control are set.
  - No permissive CORS headers are emitted, and request origins are restricted for state-changing operations.

- **Input validation and output encoding: PASS**
  - Email, phone, OTP, and recovery-code inputs are server-side validated.
  - Dynamic user-visible values inserted with `innerHTML` are HTML-escaped through `esc`.
  - There are no database queries, so parameterized-query requirements are not applicable to this in-memory implementation.

- **No sensitive values in URLs, persistent browser storage, or server logs: PASS**
  - OTP secrets, recovery codes, session tokens, and mock OTPs do not appear in URL query strings.
  - No `localStorage`, `sessionStorage`, or non-HttpOnly cookie persistence is used.
  - The deliberate browser-console test logging meets the stated testing requirement.

- **QR-code option is functional: FAIL**
  - The custom QR encoder does not reserve QR format-information modules before placing data bits.
  - In `paint()`, data is written into initially `null` format-information positions, then `format(mask)` overwrites those positions. This loses/shifts encoded data bits and can produce an invalid/unscannable QR code.
  - The `paint()` restoration logic is also faulty because `const old = modules` retains a reference to the same mutable matrix rather than a copy, so mask evaluation mutates the shared module state.
  - Since the UI offers QR setup, the QR option must actually work.

- **One clear primary action per screen: FAIL**
  - After a successful recovery-code verification, the existing primary “Check backup code” button remains and a new primary “Finish MFA enrolment” button is appended.
  - This leaves two visually primary actions on the same screen, contrary to the requirement to present one clear primary action per screen.

## FAILING_ITEMS

- Real authenticator OTPs are not single-use. `/api/otp` accepts the same valid TOTP repeatedly because it does not check or record previous successful use.
- The inline QR generator is technically incorrect:
  - QR format-information cells are not reserved before data placement.
  - Data is written into format cells and overwritten later.
  - The module matrix restoration mechanism aliases instead of cloning the matrix.
  - The QR code may not be scannable despite being offered in the UI.
- The recovery-code success state shows both “Check backup code” and “Finish MFA enrolment” as primary actions, violating the one-primary-action UX requirement.

## NEW_TASKS

1. Update `/api/otp` to enforce replay prevention:
   - Reject verification if `state.otpUsed` is already true.
   - Store a server-side identifier for the accepted TOTP time-step/code and reject reuse, including within the allowed clock-skew window.
   - Return a plain-language message explaining that the code was already used and instructing the user to use a fresh code if appropriate.

2. Replace or repair the QR encoder:
   - Reserve all QR functional patterns, including format-information cells, before data placement.
   - Correctly clone/reset the module matrix for each mask candidate rather than aliasing it.
   - Validate the generated `otpauth://` URI QR output with a QR scanner/decoder for the supported provisioning URI length.

3. Render a distinct successful recovery-verification state:
   - Remove or disable the “Check backup code” action once verification succeeds.
   - Show the success confirmation and only the “Finish MFA enrolment” primary action.

## DECISION

**FAIL**