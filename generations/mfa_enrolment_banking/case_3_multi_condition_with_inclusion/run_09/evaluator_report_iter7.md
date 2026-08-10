## SUMMARY

The artifact is a single `app.ts` Bun HTTPS SPA with substantial security controls, session ownership checks, CSRF protection, secure headers, encrypted OTP-secret storage, recovery-code hashing, rate limiting, accessible mobile-oriented UI, and working deterministic mock flows. However, it does not provide a real scannable QR code, despite presenting it as an authenticator QR code, and its advertised `otpauth://` setup is not interoperable with a standard authenticator/TOTP implementation. These are material failures for the authenticator-provisioning requirement.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun server and browser SPA**
  - The server, HTML, CSS, and vanilla browser JavaScript are all contained in `app.ts`.
  - It uses `Bun.serve` directly, with no framework, bundler, compiler step, or external asset dependency.

- **PASS — HTTPS/TLS configuration**
  - Bun is configured with `certs/cert.pem` and `certs/key.pem`.
  - The application binds as an HTTPS server and sends HSTS headers.

- **PASS — Responsive, mobile-oriented UX**
  - The UI has a constrained mobile layout, responsive styles for narrow screens, large form controls, readable spacing, and clear progression.
  - Input fields use appropriate `autocomplete`, `inputmode`, and password-manager-friendly attributes.

- **PASS — Dyslexia/inclusivity-oriented UI**
  - Instructions are generally short and plain-language.
  - The interface avoids animations, countdowns, and flashing content.
  - It provides examples for expected email, identity-code, OTP, and recovery-code inputs.
  - It provides retry/resend/refresh actions and specific corrective error messages.

- **PASS — Deterministic mocked identity, authenticator, and recovery values**
  - The identity code, mock authenticator OTP, and recovery codes are returned to the client and logged via browser `console.log`.
  - Verification of those deterministic mock values works in `TEST_MODE`.

- **FAIL — Functional QR-code authenticator provisioning**
  - `qrVisual()` creates a pseudo-random canvas pattern based on a hash of the URI. It is not a standards-compliant QR code and cannot be scanned by an authenticator application.
  - The UI tells users to “Scan this code in your authenticator app,” but the displayed image does not encode the provisioning URI.

- **FAIL — Standard authenticator / TOTP interoperability**
  - The server advertises a standard `otpauth://totp/...` URI with `algorithm=SHA1`, `digits=6`, and `period=30`.
  - However, `totp()` signs `Buffer.from(counter).toString("base64url")`, i.e. the text representation of the counter, rather than the required raw eight-byte HOTP counter.
  - Therefore, when `TEST_MODE` is disabled, standard authenticator-generated TOTP codes will not verify against this implementation.
  - In `TEST_MODE`, the server accepts only the custom `mockOtpForSecret()` value, not the normal TOTP code generated from the displayed/manual secret. A user who enters the displayed secret into a real authenticator will receive a standard TOTP that the server rejects.

- **PASS — Manual provisioning detail and copy support**
  - The secret and provisioning URI can be revealed and copied.
  - Recovery codes can be copied individually or as a set.
  - Secrets are kept in in-memory client variables rather than browser persistent storage.

- **PASS — Authorization and IDOR protection**
  - MFA state-changing and owner-data endpoints use the session-derived authenticated owner via `owner(req)`.
  - Request bodies explicitly reject `userId`, `accountId`, and `redirect` fields, reducing identifier manipulation and open-redirect risks.
  - There is no client-supplied account identifier used for MFA operations.

- **PASS — CSRF protections**
  - State-changing requests require an `X-CSRF-Token`.
  - Tokens are session-bound and compared with `timingSafeEqual`.
  - The session cookie is `SameSite=Strict`, `Secure`, and `HttpOnly`.

- **PASS — Secure headers and clickjacking protection**
  - The application sends CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, and `Cache-Control: no-store`.
  - Inline script and style execution is controlled by per-response CSP nonces.

- **PASS — Secure session lifecycle**
  - Sign-in deletes the prior session and creates a new session identifier.
  - Idle and absolute timeouts are enforced.
  - Logout deletes the server-side session and clears the cookie.

- **PASS — Secret and recovery-code storage**
  - The currently provisioned OTP secret is AES-GCM encrypted in server-side session state.
  - Recovery codes are salted and PBKDF2-hashed.
  - Cryptographically secure random generation is used for session IDs, CSRF tokens, OTP secrets, IVs, salts, and production recovery codes.

- **PASS — Verification protection**
  - Identity codes are single-use and expire.
  - OTP setup details expire and refresh invalidates the old OTP secret.
  - Recovery codes are single-use.
  - Failed identity, OTP, and recovery attempts are rate-limited with a five-minute lockout.

- **PASS — Input validation and output handling**
  - Email, phone, identity code, OTP, and recovery-code formats are validated server-side.
  - The client predominantly inserts dynamic values using `textContent`; generated HTML values are server-controlled codes rather than arbitrary user input.
  - Generic top-level server errors are returned without stack traces.

## FAILING_ITEMS

- The displayed “Authenticator QR code” is not a QR code. It is a hash-based decorative canvas pattern and cannot be scanned to provision an authenticator.
- The standard TOTP implementation is incorrect because it HMACs a Base64URL text string of the counter rather than the raw eight-byte counter required by RFC 4226/RFC 6238.
- The provisioned secret/URI cannot be used successfully with a normal authenticator during `TEST_MODE`, because verification accepts only the nonstandard deterministic mock code. This makes the UI’s instruction to scan the authenticator setup code misleading and non-functional.

## NEW_TASKS

1. Replace `qrVisual()` with an embedded, standards-compliant QR encoder that encodes the exact `provisioningUri` value, without external network assets or dependencies.
2. Correct `totp()` so the HMAC input is the raw eight-byte counter (`Uint8Array(8)`), not a Base64URL-encoded string representation of that counter.
3. Update OTP verification so a real RFC 6238 TOTP generated from the shown secret is accepted, including in `TEST_MODE`; retain the deterministic mock OTP as an additional accepted test value and browser-console test aid.
4. Update the authenticator setup wording only after the QR and TOTP behavior are corrected, so “scan this code” and “enter its six-digit code” accurately describe working behavior.

## DECISION

**FAIL**