## SUMMARY

The artifact is a single `app.ts` Bun HTTPS SPA with a generally strong mobile-oriented MFA flow, CSRF checks, secure cookie attributes, security headers, encrypted in-memory MFA secret storage, hashed recovery codes, and usable copy/print/retry UI controls. However, it does not fully meet the functional and security requirements. Most significantly, the sign-in flow grants every valid email/phone submission access to the same Marcus account, the displayed “QR” is not a valid scannable QR code, OTP lockout can be bypassed by reissuing a challenge, and sensitive values are displayed in an on-page Logs panel.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no external assets/build tooling**
  - The server, HTML, CSS, and browser JavaScript are contained in `app.ts`.
  - It uses `Bun.serve()` directly and does not use frameworks, package dependencies, bundlers, or external network calls.

- **PASS — HTTPS/TLS server configuration**
  - `Bun.serve()` is configured with `certs/cert.pem` and `certs/key.pem`.
  - The session cookie is marked `Secure`, consistent with HTTPS-only deployment.

- **PASS — Responsive mobile SPA and dyslexia-conscious presentation**
  - The layout uses a constrained mobile-friendly width, readable font sizing, generous line spacing, clear step labels, short instructions, examples, icons, and large controls.
  - There are no animations, countdowns, flashing elements, or reading time limits.
  - The flow has one main primary action per step and clear success/error feedback.

- **PASS — Manual entry, copy, reveal/hide, and recovery-code storage support**
  - The setup key is displayed and can be copied, hidden, and revealed.
  - OTP input supports `autocomplete="one-time-code"` and numeric input.
  - Recovery codes can be copied and printed/saved as PDF.
  - Recovery codes are shown in the UI and logged to the browser console as required for mock testing.

- **FAIL — QR-code provisioning option is not functional**
  - `drawQR()` creates a pseudo-random canvas pattern rather than a standards-compliant QR code.
  - It is not encoded from `provisioningUri` and cannot be scanned by an authenticator application.
  - The generated setup secret is Base64URL text rather than a standard Base32 TOTP secret, so authenticator applications may reject it even if manually pasted.

- **FAIL — Authentication and account ownership enforcement**
  - Every successful `/api/signin` request, regardless of supplied email and phone, is assigned `userId = "account-marcus-demo"`.
  - As a result, any caller who submits syntactically valid contact values receives a session authorized to modify the same account’s MFA state and recovery codes.
  - This violates the requirement that only the authenticated account owner may view or modify their own MFA settings.
  - `/api/identity` only validates the syntax of the submitted email and phone; it does not confirm that they match the signed-in account’s stored details.

- **PASS — Server-side authorization and anti-IDOR checks on protected MFA endpoints**
  - Protected state-changing MFA/recovery endpoints use `requireProtected()`.
  - The server derives the account exclusively from `session.userId`, rejects supplied account identifiers, and does not accept user/account IDs from clients.
  - This is structurally good, but is undermined by the shared-account sign-in issue above.

- **PASS — CSRF protection for state-changing authenticated endpoints**
  - State-changing protected routes require a session CSRF token and same-origin HTTPS `Origin` validation.
  - Cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`.

- **PASS — Security headers and restricted browser policy**
  - The application sends CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, `Permissions-Policy`, and `Cache-Control: no-store`.
  - CORS is not opened broadly; only accepted trusted localhost HTTPS origins can receive an ACAO response.

- **PASS — Secret and recovery-code handling at rest**
  - MFA secrets are encrypted using AES-GCM before being retained in the account/session structures.
  - Recovery codes use CSPRNG generation and are stored as SHA-256 hashes rather than plaintext.
  - No browser storage APIs or non-HttpOnly cookies are used for secrets or session tokens.

- **FAIL — OTP entropy requirement is not met**
  - Every OTP challenge is the fixed value `"123456"`.
  - This is not generated with sufficient entropy and is predictable across every session and challenge.
  - While deterministic mocks are requested for testing, this implementation does not meet the explicit security requirement that verification codes/OTPs be generated with sufficient entropy.

- **FAIL — OTP lockout can be bypassed**
  - `/api/mfa/verify` tracks failed attempts and locks the current challenge after five failures.
  - However, `/api/mfa/reissue` immediately creates a new challenge with `failures: 0` and `lockedUntil: 0`.
  - An attacker can avoid the lockout by repeatedly requesting fresh codes and continuing guesses.
  - There is also no failed-attempt rate limiting for `/api/recovery/use`.

- **FAIL — Sensitive data is exposed in an on-page log**
  - The dedicated visible `Logs` panel displays the MFA setup secret, test OTP, and recovery codes.
  - The security requirements prohibit exposing OTP seeds, OTPs, and backup codes in logs.
  - Browser `console.log` is explicitly required for mock testing, but the additional visible page log is unnecessary and increases exposure.

- **PASS — Input validation, safe rendering, generic errors, and safe redirects**
  - Server-side validation exists for email, phone, OTP, and recovery-code formats.
  - User input is not inserted into HTML; dynamic code rendering uses `textContent`.
  - Errors are generic and do not expose stack traces.
  - Redirect values are allow-listed, and no client-controlled external redirect is performed.

- **PASS — Session lifecycle controls**
  - Sessions are regenerated at sign-in, have idle and absolute timeout checks, and are invalidated at logout.
  - Cookies are cleared on logout.

## FAILING_ITEMS

- Any syntactically valid email/phone pair can sign in as the shared `account-marcus-demo` account and alter Marcus’s MFA/recovery settings.
- Identity confirmation does not compare submitted contact details against the authenticated account’s contact details.
- The canvas “QR pattern” is not a real QR code and is not based on the provisioning URI.
- The provisioning secret uses Base64URL rather than standard Base32 encoding expected by TOTP authenticator apps.
- OTPs are always `123456`, which fails the sufficient-entropy requirement.
- OTP lockout is reset by `/api/mfa/reissue`, allowing unlimited brute-force attempts through challenge reissuance.
- Recovery-code verification has no failed-attempt rate limit or lockout.
- The visible Logs panel exposes setup secrets, OTPs, and recovery codes in a page log.

## NEW_TASKS

1. Replace the shared-account sign-in behavior with a server-side authenticated demo-account model that binds each session only to its legitimate account; reject invalid demo credentials with a generic non-enumerating message.

2. Update `/api/identity` to verify that the submitted normalized email and phone match the authenticated session account before setting `identityVerified = true`.

3. Generate a standard Base32 TOTP secret and implement a standards-compliant, scannable QR encoder in the inline browser JavaScript that encodes the returned `otpauth://` provisioning URI.

4. Replace the globally fixed OTP with a cryptographically secure, time-bound simulated OTP, return it only in the authorized browser response for required mock-console testing, and retain only its hash server-side.

5. Preserve OTP failure and lockout state across code reissues, rate-limit reissue requests, and add equivalent failed-attempt rate limiting/lockout to recovery-code verification.

6. Remove the visible in-page Logs panel and its sensitive-value rendering; retain only the explicitly required browser `console.log` output for mock OTP and recovery-code testing.

## DECISION

**FAIL**