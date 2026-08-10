## SUMMARY

The artifact is a strong single-file Bun HTTPS SPA with substantial security controls, responsive mobile UI, CSRF protection, secure cookies, session expiry, rate limiting, encrypted OTP-secret storage, hashed recovery codes, and accessible/dyslexia-conscious screens. However, it does not fully meet the requirements because the custom QR encoder is technically invalid for the generated provisioning URI and can produce an unscannable QR code. The mock values are also cryptographically random/time-dependent rather than deterministic as explicitly required for testing.

## FUNCTIONAL_CHECK

- **Single `app.ts` file containing Bun server, HTML, CSS, and browser JavaScript — PASS**
  - The complete application is contained in one TypeScript file.
  - It uses `Bun.serve()` directly and does not require a bundler, framework, external asset, or build step.

- **TLS server using the provided certificate paths — PASS**
  - The server uses `certs/cert.pem` and `certs/key.pem` in the Bun TLS configuration.
  - The app is served over HTTPS and emits HSTS.

- **Mobile-responsive, dyslexia-conscious UI — PASS**
  - The UI has a narrow mobile layout, legible font sizing, increased letter/line spacing, plain-language text, examples for expected codes, prominent primary actions, consistent step labels, and non-moving content.
  - Inputs support `autocomplete="one-time-code"` and relevant autofill hints.
  - Setup secrets and recovery codes have show/hide and copy actions.

- **Sign-in, identity verification, authenticator provisioning, OTP verification, recovery-code flow, regeneration, and logout — PASS**
  - Internal navigation is implemented through client-side page functions and API requests.
  - Verification works with server-generated identity codes, TOTP values, and recovery codes.
  - Recovery codes are one-time use and replacement codes invalidate prior codes.

- **Browser-console mock delivery and test visibility — PARTIAL / FAIL**
  - Identity and authenticator test codes are logged in the browser console, and backup codes are logged after generation.
  - However, the values are generated using random secrets and the current time. They are not deterministic mock values as required.
  - The current OTP also changes according to a five-minute time slot, so it is not stable for repeatable testing.

- **Manual authenticator setup and QR option — FAIL**
  - The manual secret and provisioning URI can be copied and used manually, which is correct.
  - The QR encoder is not standards-compliant for the actual payload produced:
    - It hardcodes QR Version 6-L capacity (`136` data codewords / `1088` data bits).
    - The generated provisioning URI is approximately 140 bytes before QR mode and length overhead, exceeding Version 6-L byte-mode capacity.
    - The code silently truncates excess payload bytes via `raw.slice(...)`, while retaining a byte-length field for the original full URI.
    - Its Reed–Solomon generator calculation is not a valid QR generator-polynomial implementation, so error-correction codewords are not correctly generated.
  - As a result, the displayed canvas cannot be relied upon to scan or provision the correct authenticator URI.

- **Server-side authorization and IDOR resistance — PASS**
  - API state is associated with the authenticated server-side session and fixed account owner.
  - No user identifier is accepted from the client for MFA operations.
  - Manipulating guessed user IDs cannot select another account.

- **CSRF protection for state-changing requests — PASS**
  - State-changing endpoints require a matching server-side CSRF token and a trusted `Origin`.
  - Session cookies use `SameSite=Strict`.

- **Security headers and CORS restrictions — PASS**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, and no-store caching are present.
  - CORS is restricted to an explicit localhost allow-list.

- **Secure session handling — PASS**
  - Cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - Idle and absolute timeouts are implemented.
  - A new random session identifier is issued after sign-in.
  - Logout removes the server session and expires the cookie.

- **Secret and recovery-code protection at rest — PASS**
  - Pending and active OTP secrets are encrypted using AES-GCM with a non-extractable generated AES key.
  - Recovery codes are generated using `crypto.getRandomValues`, salted, hashed, and marked used after successful verification.
  - No secrets, sessions, or codes are persisted in browser storage.

- **Input validation, output encoding, and redirect safety — PASS**
  - Server input is type/length validated and format-validated for email, OTP, and recovery codes.
  - The client uses DOM APIs and `textContent`, avoiding unsafe HTML insertion.
  - No redirect parameter or open-redirect behavior exists.

- **Single-use, time-bound verification codes and failed-attempt controls — PASS**
  - Identity codes expire.
  - TOTP values are time-bound and previously accepted time slots cannot be replayed.
  - Recovery codes become unusable after use.
  - Identity, OTP, and recovery verification have failure counters and lockouts.

## FAILING_ITEMS

- **The QR code implementation is invalid and insufficient for the generated `otpauth://` URI.**
  - The fixed Version 6-L encoder does not have sufficient payload capacity for the generated URI.
  - The implementation truncates the URI data, so the QR payload does not match the displayed/copyable provisioning URI.
  - The Reed–Solomon generator/error-correction implementation is not a valid QR error-correction implementation.
  - This breaks the required QR authenticator-enrolment path.

- **Mock verification values are not deterministic.**
  - Identity check codes, authenticator secrets, recovery codes, and test OTPs are random.
  - Authenticator test OTPs additionally depend on `Date.now()`.
  - This does not meet the explicit requirement for deterministic mock values suitable for repeatable testing.

## NEW_TASKS

1. Replace the custom fixed Version 6-L QR implementation with a verified standards-compliant QR encoder that:
   - selects a QR version/error-correction level that fits the complete provisioning URI,
   - correctly generates Reed–Solomon error-correction blocks,
   - correctly applies QR block interleaving and masking, and
   - is tested by scanning the rendered QR code with a standard authenticator or QR decoder.

2. Make testing-mode identity, authenticator, and recovery mock values deterministic and repeatable while preserving the required server-side validation behavior.
   - Use clearly marked demo/test constants or deterministic derivation for the mock identity code, test OTP, and recovery codes.
   - Ensure the exact displayed/browser-console values always verify successfully.

## DECISION

FAIL