## SUMMARY

The artifact is a single `app.ts` Bun HTTPS SPA with a working sign-in, identity-code, authenticator, backup-code, and logout flow. It has strong foundations for session ownership, CSRF, headers, input validation, escaping, and encrypted/hashed MFA material. However, it does not meet all security and UX requirements: authenticator and recovery verification are not rate-limited or locked, production OTP handling is deterministic rather than securely generated/verified, the generated QR code is structurally incomplete for QR Version 8, and important retry/re-request/reveal UX actions are missing.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no external assets/build tooling**
  - The complete server, HTML, CSS, and browser JavaScript are contained in `app.ts`.
  - It uses Bun’s built-in serving and Node’s standard `fs` import only.
  - TLS files are read from the required `certs/cert.pem` and `certs/key.pem` paths.

- **PASS — HTTPS/TLS server and secure transport headers**
  - `Bun.serve` is configured with TLS certificate and key material.
  - HSTS, `X-Content-Type-Options: nosniff`, CSP, `X-Frame-Options: DENY`, and `frame-ancestors 'none'` are returned.
  - Session cookies include `HttpOnly`, `Secure`, and `SameSite=Strict`.

- **PASS — Server-side session ownership and IDOR protection**
  - MFA management endpoints use `owner(r)`, which requires a valid server-side session with `stage === "mfa"` and the expected account ID.
  - The client never submits a user ID, so guessed or manipulated user identifiers cannot select another account’s MFA data.
  - State remains server-owned in the in-memory session map.

- **PASS — CSRF protection for state-changing MFA actions**
  - State-changing operations require the `x-csrf-token` header to match the session token.
  - MFA state-changing endpoints such as authenticator setup, verification, backup-code generation/regeneration, recovery-code verification, and logout are protected.

- **PASS — Input validation and client-side output escaping**
  - Email, password, OTP, and recovery-code input are bounded and validated server-side.
  - OTP and recovery-code validation reject overlong input rather than silently truncating it.
  - Client-rendered dynamic messages and codes are escaped before insertion with `innerHTML`.
  - Redirects are not accepted from request input, avoiding open redirects.

- **PASS — MFA secret and backup-code protection at rest**
  - Authenticator setup secrets are encrypted using AES-GCM before being retained in server session state.
  - Backup codes are generated using cryptographic randomness outside test mode and stored as SHA-256 hashes with a random pepper.
  - Session identifiers and secrets are not written to browser storage.

- **FAIL — Verification attempts are not consistently rate-limited or locked**
  - Identity verification has an attempt counter and lock state, but `clearLock()` is never called. Once the ten-minute lock expires, `identityFails` remains at or above `MAX`, causing the next incorrect code to immediately lock the user again.
  - `/api/authenticator/verify` has `otpFails` and `otpLocked` fields available in the session type, but never increments or checks them.
  - `/api/recovery/verify` has `recoveryFails` and `recoveryLocked` fields available, but never increments or checks them.
  - This fails the requirement to rate-limit and lock out repeated failed verification attempts.

- **FAIL — Production OTP/authenticator verification is deterministic and not securely generated**
  - `secret()` uses a deterministic setup secret whenever `NODE_ENV` is not production, which is acceptable only for explicit test simulation.
  - More importantly, production still sets identity verification to the fixed value `"123456"` and authenticator verification accepts only the fixed value `"654321"`.
  - `/api/authenticator/verify` does not validate a TOTP derived from the enrolled authenticator secret; it merely compares against a constant.
  - Therefore, production verification codes are not generated with sufficient entropy and are not authenticator-secret-based as required.

- **FAIL — QR-code option is not reliably functional**
  - The QR implementation declares and creates a Version 8 QR code (`49 × 49` modules).
  - QR Versions 7 and above require version-information BCH fields in two locations. The implementation writes format information but does not write Version 8 version-information bits.
  - The omitted regions are subsequently treated as data modules, making the resulting QR symbol non-compliant and potentially unscannable.
  - Because scanning the offered QR code may fail, the QR-code setup option does not meet the functional requirement.

- **FAIL — Retry, re-request, reveal/hide, and confirmation UX is incomplete**
  - `/api/identity/send` exists but the UI provides no “send again” or “request a new code” action.
  - There is no visible way to request fresh authenticator setup details while on the authenticator-details screen.
  - Recovery codes are displayed but cannot be hidden/revealed. There is also no UI path to regenerate them despite the server endpoint existing.
  - The Copy button performs `navigator.clipboard.writeText()` but gives no plain confirmation of success or a helpful failure message if clipboard permission is unavailable.
  - These omissions conflict with the requirement to let users retry, re-request, reveal/hide, and receive clear confirmation after actions.

- **PARTIAL / FAIL — Dyslexia-supportive help availability**
  - The typography, spacing, short copy, code examples, mobile sizing, lack of animation, and visible step indicator are good.
  - However, the requirement says brief help or hints should be easy to find at every step. There is no consistent help affordance, and the unused `details` CSS does not provide actual help content.
  - Several key recovery actions are unavailable rather than explained through a brief, easy-to-find hint.

- **PASS — Browser mock behavior and no server logging of sensitive values**
  - In test mode, identity OTP, authenticator test code, provisioning URI, and recovery codes are logged from browser JavaScript via `console.log`, as required for testing.
  - The server does not log these sensitive values.
  - Sensitive values are not placed in URL query strings or reflected in server error output.

- **PASS — Generic error handling and restricted CORS**
  - The outer request handler returns a generic error response rather than a stack trace.
  - CORS only returns credentialed access headers for the localhost allow-list and rejects untrusted `Origin` headers.

## FAILING_ITEMS

- Authenticator verification has no failed-attempt counter, rate limit, or lockout enforcement.
- Recovery-code verification has no failed-attempt counter, rate limit, or lockout enforcement.
- Identity lockout state is not properly reset after its expiry because `clearLock()` is never used.
- Production identity OTP is always `"123456"` instead of a securely generated, time-bound code.
- Production authenticator verification always accepts `"654321"` rather than validating a TOTP based on the generated authenticator secret.
- The Version 8 QR generator omits required version-information modules, so the QR code is not standards-compliant and may not scan.
- The UI does not expose the implemented identity-code resend endpoint.
- The UI lacks a visible action to request fresh authenticator setup details.
- The UI lacks recovery-code hide/reveal and regeneration controls.
- Clipboard copying has no user-facing success confirmation or actionable failure handling.
- Brief help/hints are not consistently available at every stage.
- Requirement-mapping comments are limited and do not clearly map all major implementation areas to the stated requirement sections.

## NEW_TASKS

1. Implement and enforce failed-attempt tracking, rate limiting, and ten-minute lockouts for identity OTP, authenticator OTP, and recovery-code verification; reset counters correctly once a lock expires and when an appropriate new code/setup is issued.

2. Replace production fixed verification values with secure behavior: generate a cryptographically random, time-bound identity OTP and implement authenticator-secret-based TOTP validation for the enrolled secret. Keep deterministic values only in an explicitly isolated test mode.

3. Correct the in-file QR generator by encoding the required Version 8 version-information BCH fields, or replace it with a verified standards-compliant in-file QR implementation that supports the provisioning URI length.

4. Add UI controls for “send code again,” “show new setup details,” and recovery-code regeneration, with clear plain-language success and next-step messages.

5. Add recovery-code hide/reveal controls and ensure users can safely re-display saved codes during the enrolment screen without unnecessary re-entry.

6. Make clipboard copying robust: await `navigator.clipboard.writeText`, show a clear success message, and provide a plain-language fallback/error message when clipboard access is unavailable.

7. Add a consistent, short help/hint affordance to each enrolment step.

8. Expand code comments so the server security controls and client accessibility controls are explicitly mapped to the relevant requirement sections.

## DECISION

FAIL