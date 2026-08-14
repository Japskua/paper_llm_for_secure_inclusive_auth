## SUMMARY

The artifact is a single-file Bun/TLS SPA with a generally strong MFA flow, secure session cookies, CSRF checks, server-side ownership checks, encrypted OTP secrets, hashed recovery codes, responsive accessible UI, browser-only mock logging, and working manual setup/recovery-code paths. However, it cannot be accepted because the offered QR provisioning option is technically invalid, and server-side input handling truncates overlong values before validation, allowing malformed values with valid prefixes to be accepted.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with inline HTML, CSS, and vanilla browser JavaScript**
  - The full server, page template, CSS, and client-side JavaScript are contained in `app.ts`.
  - No frameworks, bundlers, compilation steps, or external frontend assets are used.
  - TLS certificates are read from the required `certs/cert.pem` and `certs/key.pem` paths.

- **PASS — Mobile-responsive, dyslexia-conscious MFA UI**
  - The UI includes a viewport meta tag, constrained mobile layout, generous padding, readable font sizing, increased letter spacing, short instructions, clear primary actions, hints, semantic labels, and password/OTP autofill attributes.
  - Screens are predictable and clearly labelled by step.
  - There are no auto-updating, flashing, or moving elements.

- **PASS — Sign-in, identity verification, authenticator setup, backup-code generation, recovery-code verification, and logout flows are implemented**
  - Sign-in transitions to identity verification.
  - Identity codes can be resent and are verified server-side.
  - Authenticator setup supports setup-link copying, manual-secret copying/reveal, code verification, retries, and setup regeneration.
  - Backup codes can be generated, copied, regenerated, and verified as single-use codes.
  - Logout invalidates the server session and clears the cookie.

- **PASS — Mock values are returned to the browser UI flow and logged in the browser**
  - In non-production test mode, mock identity OTPs, authenticator verification code, authenticator secret/provisioning URI, and recovery codes are returned to the client.
  - The browser-side `fixture()` function sends these values to `console.log`, satisfying the explicit testing/mock requirement.

- **FAIL — QR-code provisioning option works correctly**
  - The custom QR encoder is not standards-compliant despite its comment.
  - It labels itself as “Version 8, byte mode, error correction L”, but encodes Version 8 byte-mode character count incorrectly as 16 bits. QR Versions 1–9 require an 8-bit byte-mode character-count field.
  - It also uses `192` data codewords split into two 96-byte blocks. Version 8-L requires 194 data codewords, normally arranged as two 97-byte blocks, with corresponding error correction/interleaving.
  - The generated SVG may look QR-like but is unlikely to be scannable by authenticator applications. Since the app offers QR setup as an option, that option must function.

- **FAIL — Server-side input validation rejects malformed/overlong input safely**
  - The `clean()` function uses `.slice(0, max)` before validation.
  - This permits malformed values to become valid after truncation. For example:
    - An OTP such as `123456anything` becomes `123456` and can be accepted.
    - A recovery code such as `ABCD-1234-extra` becomes `ABCD-1234` and can be accepted.
    - A password longer than 256 characters with the valid password as its prefix can be truncated to the valid password.
  - This conflicts with the requirement to validate server-side input before use. Inputs exceeding a maximum length must be rejected, not silently transformed into accepted credentials/codes.

- **PASS — Server-side authorization and IDOR prevention**
  - MFA state-changing and MFA-data endpoints derive the account identity from the server session rather than accepting a user ID from the client.
  - The `owner()` function requires the authenticated session to have `stage === "mfa"` and the expected account ID.
  - No MFA endpoint exposes arbitrary account selection or user-ID parameters.

- **PASS — CSRF protection for state-changing operations**
  - State-changing endpoints require a session-bound `x-csrf-token`.
  - Session cookies use `SameSite=Strict`.
  - CSRF tokens are rotated when the user moves from identity verification into the MFA stage.

- **PASS — Secure transport, headers, and session-cookie settings**
  - The server is configured with TLS.
  - HSTS, CSP, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, Referrer Policy, and Permissions Policy headers are provided.
  - Session cookies are set with `HttpOnly`, `Secure`, and `SameSite=Strict`.

- **PASS — Secret/recovery-code protection at rest and browser-storage avoidance**
  - OTP secrets are encrypted with AES-GCM before being retained in the session object.
  - Recovery codes are stored as peppered SHA-256 hashes.
  - The app does not use `localStorage`, `sessionStorage`, URL query strings, or non-HttpOnly cookies for secrets/session tokens.

- **PASS — OTP expiry, code single-use behavior, rate limiting, and lockouts**
  - Identity OTPs are time-bound and marked used after successful verification.
  - Recovery codes are removed from active hashes after successful use.
  - Identity, authenticator, recovery, and sign-in paths have attempt counting and ten-minute lockouts.
  - Sessions are rotated after successful sign-in, expire by idle and absolute timeout, and are invalidated on logout.

- **PASS — XSS and redirect protections**
  - Client-rendered server messages are escaped before insertion through `esc()`.
  - Secrets and provisioning data are set with `textContent`, not interpolated into HTML.
  - There is no user-controlled redirect functionality and therefore no open redirect path.

## FAILING_ITEMS

- The QR-code generator has incorrect Version 8-L QR encoding parameters and an invalid byte-mode character-count encoding. The QR option is therefore not reliable or standards-compliant.
- Server-side `clean()` truncates inputs before validation. Overlong OTPs, recovery codes, and passwords can be accepted when their initial characters form a valid value.

## NEW_TASKS

1. Replace or correct `qrSvg()` so it produces valid, scannable QR codes for the provisioning URI:
   - Use correct QR Version 8-L block/data/error-correction parameters, or select the QR version dynamically based on URI length.
   - Encode byte-mode character count using the correct field width for the selected QR version.
   - Implement correct Reed–Solomon block grouping, interleaving, remainder bits, masking, and format information.
   - Verify the generated SVG by scanning it with a standards-compliant QR decoder/authenticator app.

2. Replace truncating validation with strict bounded validation:
   - Change `clean()` so it does not silently truncate input.
   - Reject inputs whose trimmed length exceeds the endpoint’s permitted maximum.
   - Apply this to email, password, identity OTP, authenticator OTP, and recovery-code inputs before comparing or authenticating them.
   - Return a specific user-safe error such as “This code is too long. Enter exactly 6 digits.”

## DECISION

FAIL