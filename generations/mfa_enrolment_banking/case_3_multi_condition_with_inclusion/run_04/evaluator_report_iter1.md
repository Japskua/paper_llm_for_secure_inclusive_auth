## SUMMARY

The artifact is a single-file Bun/TypeScript MFA enrolment SPA with a responsive mobile layout, TLS configuration, server-side sessions, CSRF checks, OTP provisioning and verification, recovery-code generation, and generally strong security headers. Most core flows work. However, it does not fully meet the requirements because the displayed “QR” is not a usable QR code, recovery-code verification is not rate-limited/locked out, and secrets/OTPs/recovery codes are placed in a visible in-page log despite the requirement not to expose them in logs.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no framework, bundler, compiler, or external assets**
  - All server, HTML, CSS, and client JavaScript are in `app.ts`.
  - It uses Bun directly via `Bun.serve`.
  - No external network calls, packages, frameworks, build tools, or external assets are used.

- **PASS — TLS is configured using the required certificate paths**
  - The server loads `certs/cert.pem` and `certs/key.pem`.
  - `Bun.serve` is configured with `tls: { cert, key }`.

- **PASS — Mobile-responsive, dyslexia-conscious UI**
  - The layout uses a constrained mobile shell, readable font sizes, spacing, high contrast, large controls, focus styles, and a small-screen media query.
  - Instructions are generally concise, include examples for email, phone, OTP, and recovery-code input, and avoid dense paragraphs.
  - The flow uses stable screens rather than moving or auto-updating UI.
  - The UI includes icons, clear progress indicators, retry paths, and help text.

- **PASS — Clear MFA enrolment flow and OTP verification**
  - The user can sign in, generate authenticator setup details, continue to OTP entry, verify a six-digit code, receive recovery codes, and complete enrolment.
  - OTP validation works against deterministic server-generated mock values.
  - OTPs are time-bound, accepted for the current or immediately preceding five-minute period, and are single-use by step.

- **FAIL — QR-code provisioning is not functional as a QR code**
  - `drawQr()` draws a deterministic decorative grid from the secret. It does not encode the returned `otpauth://` provisioning URI.
  - An authenticator app cannot scan this graphic to provision the secret.
  - The UI labels it as a “Simulated QR setup card,” but the requirement calls for a QR-code option when QR is offered; a non-decodable visual pattern does not satisfy that option.

- **PASS — Manual provisioning-secret option is available**
  - The user can reveal the generated Base32 secret and copy it.
  - The user can copy the provisioning URI through “Copy setup link.”
  - This reduces the need to transcribe the secret manually.

- **PASS — Clipboard support is present**
  - The provisioning URI, manual secret, and recovery codes can be copied with `navigator.clipboard.writeText`.
  - The actions are invoked from user-initiated button clicks in a secure HTTPS context.

- **PASS — Browser autofill support is present**
  - Email uses `autocomplete="email"`.
  - Phone uses `autocomplete="tel"`.
  - OTP uses `autocomplete="one-time-code"` and numeric input constraints.

- **PASS — Server-side authorization and IDOR resistance**
  - MFA endpoints derive the account exclusively from the authenticated server-side session.
  - No request accepts a user/account identifier.
  - `requireOwner()` rejects unauthenticated sessions and sessions not owned by `account.id`.

- **PASS — CSRF protections for state-changing requests**
  - Session-specific CSRF tokens are generated server-side.
  - State-changing requests require `X-CSRF-Token`.
  - Origin checks are also applied.
  - The session cookie uses `SameSite=Strict`.

- **PASS — Secure headers and clickjacking controls**
  - Responses include CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`, and `Cache-Control: no-store`.
  - CSP includes `frame-ancestors 'none'`.

- **PASS — Secure session-cookie settings and session management**
  - Cookies use `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - Sessions are server-side, rotated after sign-in, have idle and absolute expiration, and are invalidated on logout.
  - Session IDs are generated with `crypto.getRandomValues`.

- **PASS — Input validation and output handling**
  - Email, phone, OTP, and recovery-code formats are validated server-side.
  - There is no database query surface, so SQL injection does not apply to the current in-memory implementation.
  - User-controlled values are not rendered into the HTML without validation/controlled handling.
  - Redirect handling is allow-listed through `safeInternalPath`.

- **PASS — OTP rate limiting and lockout**
  - OTP failures increment `failedAttempts`.
  - After five failures, the record is locked for ten minutes.
  - Lockout messages explain what happened and how to recover.

- **FAIL — Recovery-code verification has no failed-attempt rate limit or lockout**
  - `/api/check-recovery` allows unlimited invalid recovery-code submissions.
  - The requirement requires rate-limiting and lockout after repeated failed verification attempts.
  - Recovery codes are verification credentials and must receive equivalent brute-force protections.

- **PASS — Cryptographically secure secret and recovery-code generation**
  - OTP secrets, session IDs, CSRF tokens, encryption keys, peppers, and recovery codes originate from `crypto.getRandomValues`.
  - OTP secrets are AES-GCM encrypted before storage in the in-memory MFA record.
  - Recovery codes are stored as hashes with a random pepper rather than plaintext.

- **FAIL — Sensitive secrets are exposed in a visible in-page log**
  - The client logs secrets, test OTPs, and recovery codes to the `#loglines` UI section:
    - `TEST ONLY — authenticator secret: ...`
    - `TEST ONLY — current authenticator code: ...`
    - `TEST ONLY — recovery codes: ...`
  - The security requirement explicitly says OTP seeds, OTPs, and backup codes must never be exposed in logs.
  - Browser `console.log` is explicitly required by the testing requirement, but rendering those same secrets into an on-page section titled “Logs” is unnecessary and creates an avoidable exposure.

- **PASS — Generic server error handling**
  - Top-level errors return a generic response and do not expose stack traces.
  - Server-side code does not log secrets, OTPs, recovery codes, or session tokens.

- **PASS — Internal SPA navigation works**
  - The app transitions between sign-in, setup, provisioning, verification, recovery-code, completion, and logout screens through functioning event handlers.
  - There are no broken internal hyperlinks.

## FAILING_ITEMS

- The QR graphic is not a valid QR encoding of the provisioning URI and cannot be scanned by an authenticator app.
- Recovery-code verification at `/api/check-recovery` has no rate limiting, attempt counter, or lockout behavior after repeated failures.
- Sensitive setup secrets, OTPs, and recovery codes are displayed in the visible `#loglines` “Logs” panel, conflicting with the requirement not to expose these values in logs.

## NEW_TASKS

1. Replace `drawQr(secret)` with a real, locally implemented QR encoder that encodes `provision.provisioningUri`, or remove the QR option entirely and present only the copyable provisioning URI/manual secret option.
2. Add recovery-verification failure tracking to `MfaRecord` and enforce a rate limit/temporary lockout in `/api/check-recovery`, with a clear user-facing retry message.
3. Remove the visible `#loglines` log panel and all DOM rendering of sensitive test values; retain only the explicitly required browser `console.log` output for mock/test secrets, OTPs, and recovery codes.

## DECISION

FAIL