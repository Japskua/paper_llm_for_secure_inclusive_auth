## SUMMARY

The artifact is a well-structured single-file Bun HTTPS SPA with responsive UI, protected MFA API routes, secure cookie attributes, CSRF tokens, TLS certificate loading, encrypted OTP-secret storage, hashed recovery codes, and browser-console delivery simulations. However, it does not fully meet the security requirements because identity-code verification has no rate limiting/lockout and uses a globally predictable fixed code. In addition, its advertised `otpauth://` URI and QR display are not compatible with standard authenticator applications.

## FUNCTIONAL_CHECK

- **PASS — Single-file, zero-compilation architecture**
  - All server code, HTML, CSS, and browser JavaScript are contained in `app.ts`.
  - It uses Bun directly with `serve()` and does not require frameworks, bundlers, external assets, or compilation.

- **PASS — HTTPS/TLS usage**
  - The server requires `certs/cert.pem` and `certs/key.pem` before starting.
  - The application is served over TLS on port `3000`.
  - The non-TLS listener only redirects to the TLS origin.

- **PASS — Responsive, accessible mobile SPA UI**
  - The HTML includes a mobile viewport declaration.
  - CSS provides constrained-width cards, readable typography, visible focus styles, and a small-screen media query.
  - Forms use labels, semantic sections, `autocomplete`, input modes, and error announcements.

- **PASS — Authentication/session security controls**
  - Sessions are server-side and derive user identity solely from an HttpOnly cookie.
  - Cookies use `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - Session IDs are regenerated after identity verification.
  - Idle and absolute session expiration are implemented.
  - Logout invalidates the server-side session and clears the cookie.
  - API endpoints do not accept a user ID from the client, avoiding direct IDOR exposure.

- **PASS — CSRF and state-changing endpoint protection**
  - Protected mutations require the session’s CSRF token.
  - MFA provisioning, authenticator verification, activation, backup-code regeneration, recovery-code use, and logout all validate CSRF tokens.
  - SameSite cookies add defense in depth.

- **PASS — Secret and recovery-code handling**
  - Authenticator secrets are generated with `crypto.getRandomValues`.
  - OTP secrets are stored encrypted with AES-GCM server-side.
  - Backup codes are generated with a cryptographic RNG and stored only as salted hashes.
  - Browser storage APIs are not used for secrets or sessions.
  - Backup codes are one-time use.

- **PASS — Security headers and restricted CORS**
  - HTTPS responses include CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, and `Cache-Control: no-store`.
  - CSP includes `frame-ancestors 'none'`.
  - CORS is restricted to explicitly trusted localhost origins rather than using a wildcard.

- **FAIL — Verification codes are sufficiently unpredictable and protected from brute force**
  - The identity verification code is always the fixed value `"246810"` for every session.
  - `/api/identity` has no failure counter, rate limit, or lockout. An attacker with a valid identity-phase session can make unlimited guesses during the five-minute validity period.
  - This violates the requirement that verification codes have sufficient entropy and that repeated failed verification attempts are rate-limited and locked out.

- **PASS — Authenticator and recovery verification rate limiting**
  - Authenticator OTP verification has a five-failure lockout for five minutes.
  - Recovery-code verification has a five-failure lockout for five minutes.
  - Authenticator OTPs are time-bound and protected against replay within the same time counter.

- **FAIL — Offered authenticator provisioning is not interoperable with the published provisioning URI**
  - The application exposes an `otpauth://totp/...` URI, which conventionally represents RFC-compatible TOTP provisioning.
  - The server’s `totpFor()` implementation signs the decimal string of the time counter using HMAC-SHA-256. Standard TOTP uses an eight-byte binary moving counter and typically defaults to HMAC-SHA-1 unless an `algorithm` parameter is supplied.
  - The URI does not declare `algorithm=SHA256`, and even if it did, its counter encoding does not match standard TOTP.
  - The displayed QR image is decorative simulated CSS rather than a QR encoding of `provisioningUri`.
  - Therefore, a real authenticator configured from the displayed URI/QR cannot produce the server-accepted OTP. Only the server-returned mock `testOtp` works.

- **PASS — Browser-side mock delivery and functional enrolment flow**
  - Identity codes, authenticator test codes, and recovery codes are returned to the UI and emitted through browser `console.log`.
  - The sign-in → identity verification → provisioning → OTP confirmation → backup-code display → settings/recovery/logout flow is wired through functional API calls.
  - Manual entry of the provisioning secret is available during authenticator confirmation.

## FAILING_ITEMS

- Identity verification uses the permanently predictable code `246810`, rather than a per-session cryptographically generated code with adequate entropy.
- `/api/identity` does not track failed attempts and does not rate-limit or lock identity verification after repeated invalid code or phone submissions.
- The `otpauth://` provisioning URI is incompatible with the server-side OTP calculation:
  - URI defaults do not match HMAC-SHA-256.
  - The implementation uses a decimal-string counter rather than the standard binary counter.
  - The URI does not advertise its actual nonstandard algorithm behavior.
- The rendered “QR code” is visual decoration and does not encode the provisioning URI, so it cannot be scanned by an authenticator application.

## NEW_TASKS

1. Replace the fixed identity code with a per-session, cryptographically random six-digit code; retain testability by returning it only in the mock response and logging it in the browser console as required.
2. Add identity-verification failure tracking and a five-attempt lockout/rate-limit policy to the `Session` type and `/api/identity`, equivalent to the existing authenticator and recovery-code protections.
3. Implement RFC-compatible TOTP generation and verification using an eight-byte big-endian time counter, standard dynamic truncation, and a documented algorithm.
4. Update `provisioningUri` to accurately declare the TOTP settings used by the server, including `algorithm`, `digits`, and `period`.
5. Generate a real QR code representing `provisioningUri`, or remove the scan-oriented QR presentation and clearly provide only the manual simulated setup path.

## DECISION

**FAIL**