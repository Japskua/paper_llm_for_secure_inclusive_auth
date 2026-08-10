## SUMMARY

The artifact is a strong single-file Bun HTTPS MFA prototype with owner-bound sessions, CSRF checks, secure headers, encrypted OTP seed storage, hashed recovery codes, rate limiting, and a responsive accessible UI. However, it does not fully meet the requirements because the custom QR-code implementation does not correctly encode the provisioning URI, making the offered QR setup path unreliable/non-functional. In addition, the normal (non-`?test=1`) mock identity-code flow does not deliver a usable code to the browser console or UI, so the simulated MFA journey cannot be completed without using an undocumented test query parameter.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no frameworks, bundlers, compilation, or external assets**
  - The complete server, HTML template, CSS, and browser JavaScript are contained in `app.ts`.
  - It uses `Bun.serve` directly and does not import frontend frameworks or external assets.

- **PASS — HTTPS/TLS server uses the required certificate paths**
  - The Bun server is configured with:
    - `certs/cert.pem`
    - `certs/key.pem`
  - The application serves HTTPS on port `3000`.

- **PASS — Responsive, mobile-oriented UI and generally dyslexia-conscious presentation**
  - The UI uses a narrow mobile shell, readable font stack, increased letter spacing, short instructions, generous spacing, prominent primary actions, examples, icons, and no animated/timed UI.
  - Inputs have mobile-appropriate types and autofill hints such as `autocomplete="one-time-code"`.

- **PASS — Sign-in, identity-check, authenticator, recovery-code, completion, and logout states are implemented**
  - The client has renders and server endpoints for all stages.
  - Stage transitions are server-controlled rather than client-authoritative.
  - Logout invalidates the server session and expires the cookie.

- **FAIL — Mock code delivery is not functional in the normal application flow**
  - Identity verification codes are generated server-side, but `/api/sign-in` only returns `testIdentityCode` when `?test=1` was used.
  - The browser only logs the identity code in test mode.
  - In normal mode, no SMS/e-mail delivery exists, no code is shown in the UI, and no mock code is logged in the browser. A user therefore cannot complete the identity step.
  - The requirement explicitly states that OTP delivery/provisioning/verification are simulated through browser `console.log` and mock values.

- **FAIL — The QR-code provisioning option is not correctly implemented**
  - `qrCanvas()` claims to generate a standards-compliant QR Model 2 Version 8-L QR code, but the byte-mode data stream is malformed.
  - It constructs data bytes as:
    - `const d=[64,(bytes.length>>8)&255,bytes.length&255,...bytes]`
  - For QR Versions 1–9, byte mode requires a 4-bit mode indicator followed by an **8-bit** byte count. The implementation effectively writes an incorrect 16-bit length representation and does not pack the header/payload correctly at bit level.
  - The Reed-Solomon error-correction routine also does not construct/use the required QR generator polynomial coefficients for Level L / 24 error-correction codewords.
  - Consequently, the rendered QR code cannot be relied upon to scan as the exact `otpauth://` provisioning URI. This violates the requirement that a QR/provisioning option must work.

- **PASS — Manual authenticator setup is available**
  - The Base32 seed and `otpauth://` URI can be revealed and copied.
  - The user can manually enter a six-digit authenticator code.
  - Clipboard fallback messaging is provided.

- **PASS — Server-side authorization and IDOR resistance**
  - MFA endpoints retrieve the authenticated session from the HttpOnly cookie and do not accept a user ID from the client.
  - Protected endpoints use `owner(req)` and reject unauthenticated sessions.
  - MFA state is attached to the current server-side session, preventing guessed-user-ID manipulation.

- **PASS — CSRF protection on state-changing requests**
  - POST endpoints require a per-session CSRF token.
  - The implementation validates the token with a timing-safe comparison and validates the `Origin` header against an allow-list.

- **PASS — Session security**
  - Session identifiers are generated with `crypto.getRandomValues`.
  - The session is rotated after successful sign-in.
  - Cookies use `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - Idle and absolute session expirations are enforced.
  - Logout deletes the session and expires the cookie.

- **PASS — Security headers and restrictive browser policy**
  - CSP uses a per-page nonce and includes `frame-ancestors 'none'`.
  - HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`, and `Cache-Control: no-store` are set.
  - CORS preflight requests are only allowed from the configured trusted origins.

- **PASS — OTP/recovery cryptographic handling**
  - OTP seed generation uses CSPRNG.
  - OTP seed storage is AES-GCM encrypted in server memory.
  - Recovery codes are generated with CSPRNG and retained as salted PBKDF2 hashes.
  - Verification uses timing-safe comparisons.
  - TOTP verification accepts a small clock-skew window and successful authenticator verification is single-use for the enrolment flow.

- **PASS — Input validation, safe output handling, and generic failures**
  - Inputs are type/format/length checked server-side.
  - User-controlled values are not inserted into `innerHTML`; server messages are rendered via `textContent` when updating notices.
  - Errors returned to users are generic and do not expose stack traces.

- **PASS — Failed-attempt lockout and code lifecycle controls**
  - Identity-code attempts and authenticator/recovery-code attempts are rate-limited through a five-attempt lockout.
  - Identity codes expire and become unusable after success.
  - Authenticator setup details can be refreshed, invalidating prior setup material.
  - Recovery codes are single-use and regenerating them invalidates old codes.

## FAILING_ITEMS

- The custom QR generator is not a valid QR encoder for the generated provisioning URI:
  - The QR byte-mode header and length encoding are incorrect.
  - The Reed-Solomon error-correction generation is not QR-compliant.
  - The QR code may render visually but is not dependable as a scannable `otpauth://` provisioning code.

- The default mock identity-verification path is incomplete:
  - Without `?test=1`, the generated identity code is not delivered through browser `console.log`, shown to the user, or otherwise made available.
  - This leaves the normal simulated flow unable to pass the identity step.
  - The test-mode query parameter is undocumented in the UI and is required to complete the mock flow.

## NEW_TASKS

1. Replace the custom `qrCanvas()` implementation with a verified standards-compliant, self-contained QR encoder that correctly supports byte-mode payloads, QR Version/EC block layouts, Reed-Solomon error correction, masking, format bits, and the generated `otpauth://` URI length. Keep the implementation inside `app.ts` and do not add external network dependencies.

2. Make simulated identity-code delivery usable in the normal demo flow:
   - Log the generated mock identity code in the **browser console** after sign-in and resend, consistent with the mock-delivery requirement.
   - Ensure the server never logs the code.
   - Alternatively, provide an explicit, visible demo/test-mode control and make clear that the mocked browser-console code is needed for the demo flow; it must not require an undisclosed URL query parameter.

## DECISION

FAIL