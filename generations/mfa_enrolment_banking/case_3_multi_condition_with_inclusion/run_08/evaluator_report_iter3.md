## SUMMARY

The artifact is a single-file Bun HTTPS SPA with a clear mobile MFA enrolment flow, secure headers, CSRF checks, encrypted OTP-secret storage, hashed recovery codes, and working identity/TOTP verification endpoints. However, it does not fully meet the security and functional requirements: authentication can be initiated and completed for the known account using only the email address because the mock identity code is returned to the requester; account enumeration remains possible; lockouts can be bypassed by regenerating challenges/secrets/codes; and the displayed “QR” canvas is not a valid scannable QR code.

## FUNCTIONAL_CHECK

- **Single `app.ts` file containing Bun server, HTML, CSS, and vanilla client JavaScript: PASS**
  - The complete application is contained in one file and does not use frameworks, bundlers, external assets, or external network calls.

- **Bun HTTPS server using supplied TLS certificates: PASS**
  - `Bun.serve` uses `certs/cert.pem` and `certs/key.pem` through the `tls` configuration.

- **Mobile-responsive, legible, dyslexia-aware SPA flow: PASS**
  - The layout has a constrained mobile width, responsive viewport metadata, large form controls, adequate spacing, plain language, visible step progress, non-moving UI, input examples, retry actions, and accessible focus styling.
  - The app avoids localStorage/sessionStorage and has no countdown or reading deadline.

- **Identity-code, authenticator, and recovery-code mock values available in browser console/UI demo logs: PASS**
  - The browser logs the identity verification code, authenticator secret/current code, and generated recovery codes.
  - This aligns with the explicit mock/testing requirement, despite the normal production restriction against logging secrets.

- **Identity verification and TOTP verification work deterministically: PASS**
  - The identity code is generated server-side, has expiry, single-use handling, and validation.
  - TOTP is generated and verified from the provisioned secret using HMAC-SHA-1 with a 30-second counter, including a small clock-skew window.

- **Recovery-code verification works through the server endpoint: PASS**
  - `/api/mfa/recovery/verify` validates code format, hashes submissions, consumes valid codes, and rate-limits invalid/used attempts.
  - However, it is not exposed through a user-facing recovery verification screen; see failing items.

- **QR-code option is usable and scannable: FAIL**
  - `drawQR()` does not generate a standards-compliant QR code. It simply paints bits derived from Base64 text onto a 29×29 canvas.
  - Authenticator apps cannot scan this as an `otpauth://` QR code, despite the UI saying “Scan this set-up pattern.”

- **Manual provisioning fallback is present: PASS**
  - The generated Base32 secret is displayed and can be copied, while the user can manually submit the resulting six-digit authenticator code in the following step.

- **Server-side ownership authorization / IDOR prevention: FAIL**
  - Protected endpoints do check the session and bind it to `USER.id`.
  - However, `/api/auth/signin` creates an account-owner session when a requester supplies the known email address, and returns the identity challenge code in the response. Any requester who knows `marcus@example.test` can obtain a valid session and modify that account’s MFA state.
  - This does not meet the requirement that only the authenticated account owner may view or modify MFA settings.

- **Account/user enumeration resistance: FAIL**
  - A valid known email receives `200` plus a session and challenge code, while an unknown email receives `400`.
  - This allows direct account existence testing through status/body differences.

- **CSRF protection for state-changing protected operations: PASS**
  - Protected POST routes require the session-specific `X-CSRF-Token`.
  - The session cookie is `SameSite=Strict`, and state-changing routes reject requests with invalid CSRF tokens.

- **Secure session-cookie attributes and session lifecycle: PASS**
  - The session cookie is `HttpOnly`, `Secure`, `SameSite=Strict`, and has an expiration.
  - Sessions enforce idle and absolute timeouts, are invalidated on logout, and a new identifier is generated on sign-in.

- **Secure response headers and restricted CORS: PASS**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, cache prevention, referrer policy, and restricted CORS behavior are implemented.
  - Error handling returns generic errors rather than stack traces.

- **Cryptographically secure generation and at-rest protection: PASS**
  - Tokens, OTP secrets, OTPs, and recovery codes use `crypto.getRandomValues`.
  - OTP secrets are AES-GCM encrypted in the server session state; recovery codes are stored as peppered SHA-256 hashes.
  - Secrets and session tokens are not persisted in browser storage.

- **Input validation and output encoding: PASS**
  - Email and code formats are validated server-side.
  - Client-rendered notices, codes, and demo logs are HTML-escaped before insertion through `innerHTML`.
  - There are no database queries or redirect parameters to introduce SQL injection or open redirects.

- **Rate limiting and lockout of repeated verification failures: FAIL**
  - Identity-code lockout can be bypassed by calling `/api/identity/resend`, which replaces the locked challenge with a fresh challenge whose attempt count and lock state are reset.
  - TOTP lockout can be bypassed by calling `/api/mfa/provision/new`, which resets `totpAttempts` and `totpLockedUntil`.
  - Recovery-code lockout can be bypassed by calling `/api/mfa/recovery/generate`, which resets `recoveryAttempts` and `recoveryLockedUntil`.
  - Therefore the required repeated-failure lockout is not enforceable.

- **User-facing recovery-code use flow: FAIL**
  - The backend has `/api/mfa/recovery/verify`, but no SPA screen or navigation path allows a user to enter and verify a recovery code.
  - The user can generate and save recovery codes but cannot exercise the recovery-code verification feature through the delivered mobile UI.

## FAILING_ITEMS

- The displayed QR canvas is not a genuine QR code and cannot be scanned by an authenticator app.
- The sign-in endpoint grants a session for the fixed account based on email alone and returns the identity OTP to that same requester, allowing takeover of the known mock account.
- Known versus unknown email addresses produce distinguishable sign-in responses, enabling account enumeration.
- Verification lockouts are resettable through resend, reprovisioning, and recovery-code regeneration endpoints.
- The recovery-code verification API is unreachable from the SPA, so users cannot manually enter and verify a saved recovery code through the app.

## NEW_TASKS

1. Replace `drawQR()` with an embedded, standards-compliant QR encoder that produces a valid scannable QR representation of the `otpauth://` provisioning URI; retain the displayed/copyable manual secret fallback.

2. Add a proper simulated authenticated-owner login gate before MFA enrolment, and only create the MFA session after that authentication succeeds; do not return an account-verification OTP to an unauthenticated requester in a way that permits account takeover.

3. Make sign-in responses for unknown and known accounts indistinguishable in status, message, and observable behavior until authentication is complete, preventing account enumeration.

4. Store identity, TOTP, and recovery verification failure counts/lock timestamps in lock state that cannot be reset by resending an identity code, generating a new authenticator secret, or regenerating recovery codes; reject those reset actions while the corresponding lock is active.

5. Add a recovery-code verification screen in the SPA with a manually entered `ABCD-EFGH` field, a clear primary verification action, accessible error/success feedback, and a route to `/api/mfa/recovery/verify`.

## DECISION

FAIL