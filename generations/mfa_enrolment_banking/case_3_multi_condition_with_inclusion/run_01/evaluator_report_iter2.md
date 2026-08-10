## SUMMARY

The artifact is a single `app.ts` Bun HTTPS SPA with strong coverage of the enrolment UX, session handling, CSRF checks, headers, secure cookies, server-side authorization, and accessible mobile styling. However, it fails key MFA functionality and security requirements: the provisioning QR implementation is not reliable, the server verifies a separately generated mock code rather than a TOTP generated from the provisioned authenticator secret, backup-code hashes are not strong at-rest protection, and sign-in behavior has an account-enumeration timing difference. These issues prevent acceptance.

## FUNCTIONAL_CHECK

- **PASS — Single-file, zero-compilation delivery**
  - The server, HTML, CSS, and browser JavaScript are all contained in `app.ts`.
  - It uses Bun directly and does not require frameworks, bundlers, external assets, or external network calls.

- **PASS — HTTPS/TLS server setup**
  - `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`.
  - Requests are rejected unless they are HTTPS and use an allowed local host.

- **PASS — Responsive mobile SPA and inclusive UX**
  - The layout is responsive and constrained to a mobile-friendly width.
  - It uses readable fonts, increased line/letter spacing, clear cards, visible progress steps, short instructions, examples, large input controls, and no moving content.
  - Help is present at each stage and explicitly states there is no reading timer.

- **PASS — Sign-in flow and browser autofill support**
  - Email and password fields use appropriate `autocomplete` values.
  - Client-side UX has clear error notices and prevents duplicate button actions while requests are in progress.
  - The server validates email and password input.

- **PASS — Server-side authorization / IDOR protection**
  - MFA endpoints use the authenticated session’s `userId`; they do not accept user/account identifiers from the client.
  - Manipulating a user identifier is not possible through the exposed endpoints.

- **PASS — CSRF protection for state-changing MFA actions**
  - Authenticated state-changing endpoints require a CSRF token and same-origin HTTPS origin validation.
  - The session CSRF token is generated server-side and sent only after successful sign-in.

- **PASS — Secure session cookie attributes and session lifecycle**
  - The session cookie uses `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, and a bounded lifetime.
  - Sessions have idle and absolute expirations.
  - Sessions are rotated on authentication, old sessions for the account are invalidated, and logout invalidates the session.

- **PASS — Security headers and CORS restriction**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, referrer policy, permissions policy, and `Cache-Control: no-store` are configured.
  - CORS is only enabled for the same trusted HTTPS origin.

- **FAIL — Authenticator provisioning and verification work correctly**
  - `/api/provision` generates a secret and an `otpauth://` URI, but `/api/verify-otp` does **not** validate a TOTP derived from that secret.
  - Instead, it generates an unrelated random `mockOtp`, hashes it, and accepts only that unrelated value.
  - A user who scans the QR code or manually enters the shown secret into a real authenticator app will receive a valid TOTP that the server rejects.
  - This fails the required time-based OTP authenticator flow and means the QR/manual-secret provisioning path does not actually work.

- **FAIL — QR-code option is valid and functional**
  - The custom `qrSvg` implementation writes data into format-information cells before overwriting those cells with format bits.
  - Because those cells were not reserved before data placement, the data stream becomes misaligned and the final matrix is not a standards-compliant QR encoding of the provisioning URI.
  - The offered QR option therefore cannot be relied upon to scan successfully.

- **PASS — Manual secret and copy-to-clipboard options**
  - The provisioning secret is displayed manually, can be copied, and can be hidden/revealed.
  - Recovery codes can be copied.
  - Browser clipboard failure is handled with a clear fallback message.

- **PASS — OTP validation, expiry, single-use behavior, and rate limiting**
  - OTP input format is validated.
  - OTPs are time-bound, marked single-use after successful verification, and failed attempts lock verification after five failures.
  - Recovery-code verification similarly validates format and applies a lockout.

- **PASS — Backup-code generation, display, replacement, and single-use server handling**
  - Ten recovery codes are generated, returned to the UI for the required test display/logging behavior, and only hashes are retained in the account object.
  - Regeneration replaces the prior hashes.
  - `/api/recovery/verify` removes a successfully used recovery-code hash.

- **FAIL — Strong at-rest protection for backup recovery codes**
  - Recovery codes are stored as unsalted plain SHA-256 hashes: `codes.map(sha256)`.
  - The code format has a bounded, enumerable search space, and unsalted SHA-256 is vulnerable to efficient offline guessing/precomputation if the in-memory data is exposed.
  - Use a keyed hash/HMAC with a server-side secret (or an appropriate password-hashing/KDF strategy with per-code salt) rather than raw SHA-256.

- **FAIL — No account/user enumeration in response timing**
  - The sign-in condition short-circuits when `account` is absent:
    ```ts
    !account || sha256(password) !== account.passwordHash
    ```
  - For a valid-looking password and a nonexistent email, password hashing is skipped; for an existing account, password hashing occurs.
  - This creates a measurable response-time distinction despite the generic message, contrary to the no-enumeration-in-timing requirement.

- **PASS — Input validation, output encoding, and redirect handling**
  - Server-side validation exists for email, password, OTP, and recovery-code input.
  - Dynamic values inserted through browser HTML rendering are escaped via `esc`.
  - No redirect parameter or open redirect mechanism is present.

- **PASS — No secret persistence in browser storage**
  - The code does not use `localStorage`, `sessionStorage`, or client-readable cookies for MFA secrets, OTPs, recovery codes, or sessions.
  - Temporary browser variables are cleared on completion/logout.

- **PASS — Generic production error handling**
  - The outer server handler catches unexpected errors and returns a generic error message rather than a stack trace.

## FAILING_ITEMS

- The provisioned authenticator secret is not used for OTP verification. The server accepts only a separate random `mockOtp`, so a real authenticator app configured from the QR code or manual secret cannot complete enrolment.
- The hand-written QR encoder is invalid because format-information modules are not reserved before data placement, corrupting the encoded data stream.
- Backup recovery codes are protected with unsalted raw SHA-256 rather than a strong keyed/salted at-rest verifier.
- Sign-in has an account-enumeration timing difference because password hashing is skipped for nonexistent accounts.

## NEW_TASKS

1. Replace the independent `mockOtp` verification design with RFC 6238 TOTP validation based on the generated provisioning secret; decrypt the stored secret server-side, calculate the expected TOTP using HMAC-SHA-1, enforce a short permitted clock window, and retain single-use/rate-limit behavior as appropriate for the simulated enrolment flow.

2. Keep the required browser test logging by returning/logging a test TOTP derived from the same provisioned secret, rather than returning an unrelated random six-digit code.

3. Replace `qrSvg` with a standards-compliant embedded QR encoder that correctly reserves all functional modules, applies valid error correction and masking, supports the provisioning URI capacity, and produces a scannable QR code for the exact returned `otpauth://` URI.

4. Replace raw `sha256` backup-code storage with a strong verifier, such as HMAC-SHA-256 using a server-only pepper/key, and use constant-time comparison when checking a submitted recovery code.

5. Make sign-in password verification timing-independent of account existence by always computing a password hash/KDF comparison using either the account hash or a fixed dummy hash, while retaining the same generic sign-in response.

## DECISION

FAIL