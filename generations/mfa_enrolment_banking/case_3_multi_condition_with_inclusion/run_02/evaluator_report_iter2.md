## SUMMARY

The artifact is a single-file Bun HTTPS SPA with a strong overall structure. It includes a responsive mobile UI, accessible plain-language MFA steps, CSP nonce handling, authenticated API endpoints, CSRF headers, secure session cookies, TOTP support, QR generation, recovery-code hashing, and browser-side mock logging in demo mode. However, it does not fully meet the stated requirements because normal-mode OTP delivery is not simulated in the browser, TOTP values can be replayed, pending recovery codes are stored in plaintext server memory, and sign-in processing does not adequately provide uniform timing protection against account enumeration.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no framework, build tool, compilation step, or external assets**
  - Everything is contained in `app.ts`: Bun server, HTML, inline CSS, and browser JavaScript.
  - The QR encoder is implemented locally and no external image, script, font, or network resource is loaded.

- **PASS — Bun serves the application over TLS using the specified certificate paths**
  - `Bun.serve()` is configured with `tls.cert` and `tls.key` read from `certs/cert.pem` and `certs/key.pem`.
  - The app only exposes the HTTPS Bun listener.

- **PASS — Responsive, mobile-oriented, dyslexia-conscious UX**
  - The layout has a constrained mobile width, readable font sizing, generous line-height and letter spacing, short instructions, visible current-step text, examples for code fields, large controls, clear primary actions, and help content.
  - There are no moving, flashing, or auto-updating visual elements.
  - QR, copy, reveal, resend, retry, and recovery-code regeneration options are provided.

- **FAIL — OTP delivery and deterministic mock values are consistently simulated via browser `console.log`**
  - In normal mode, `/api/signin` and `/api/identity/resend` generate an identity OTP but do not return it to the UI and therefore do not log it in the browser.
  - The client-side `demo()` function only logs identity OTPs when `EVALUATOR_DEMO=true`.
  - This means the default flow tells Marcus that a code was “sent to your phone,” but no simulated delivery mechanism exists, making normal-mode identity verification impossible without inspecting server memory.
  - The requirement explicitly requires simulated OTP delivery and browser console logging for mocks/testing.

- **PASS — Authenticator provisioning and manual secret entry support**
  - The setup screen renders a QR code for the `otpauth://` URI.
  - It can reveal the Base32 setup key and full provisioning URI.
  - Both values can be copied to the clipboard.
  - The authenticator code can be entered manually.

- **PASS — MFA flow state, routing, and recovery behavior function within the SPA**
  - The flow supports sign-in, identity verification, authenticator setup, TOTP verification, recovery-code display/regeneration/acknowledgement, post-enrolment MFA verification, and logout.
  - `/api/state`, `/api/authenticator/pending`, and `/api/backup/pending` support restoring unfinished stages after a page refresh.
  - No broken internal links are present; navigation is implemented through functioning SPA handlers.

- **PASS — Server-side authorization and IDOR prevention**
  - MFA endpoints obtain the account only from the authenticated session (`session.userId`) and do not accept a client-provided account/user identifier.
  - Requests with missing, expired, invalid, or manipulated session identifiers are rejected.
  - The sole user identifier is never selected by browser input.

- **PASS — CSRF protection for authenticated state-changing MFA requests**
  - Authenticated non-GET requests require the `X-CSRF-Token` value to match the server-side session token.
  - Session cookies use `SameSite=Strict`.
  - Origin validation rejects non-local HTTPS origins.

- **PASS — Security response headers and restrictive browser policy**
  - CSP uses per-response nonces and includes `frame-ancestors 'none'`.
  - `X-Frame-Options: DENY`, HSTS, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, `Cache-Control: no-store`, and `Cross-Origin-Resource-Policy: same-origin` are set.
  - No permissive CORS headers are emitted.

- **FAIL — OTPs are single-use and time-bound**
  - Identity OTPs are properly time-bound and marked used after a successful verification.
  - Standard TOTP verification accepts the same valid code repeatedly during its valid interval, including the ±1 interval skew window.
  - In `EVALUATOR_DEMO=true`, `demoTotpFixture: "123456"` is accepted indefinitely and is neither time-bound nor single-use.
  - This violates the explicit requirement that verification codes/OTPs be single-use and time-bound.

- **FAIL — Backup codes are always protected at rest**
  - Stored backup-code records use PBKDF2 hashes with independent random salts, which is good.
  - However, `createBackups()` stores the raw recovery codes in `record.pendingBackupCodes`.
  - `/api/backup/pending` returns this server-side plaintext array after refreshes.
  - The requirement requires backup codes to be strongly hashed or encrypted at rest; the pending plaintext array does not meet that requirement.

- **PASS — OTP secret is protected at rest**
  - Authenticator secrets are generated using `crypto.getRandomValues`.
  - Secrets are encrypted with AES-GCM using a random IV and are decrypted only for protected setup/TOTP operations.
  - They are not persisted in browser storage or non-HttpOnly cookies.

- **PASS — Input validation and output encoding**
  - Email, numeric OTP, and recovery-code formats are validated server-side.
  - The UI HTML-escapes dynamic values before inserting them with `innerHTML`.
  - Redirect parameters are not accepted, so no open redirect path exists.

- **PASS — Failure handling, rate limiting, lockout, session expiration, and logout**
  - Failed identity, TOTP, and recovery-code attempts share a five-attempt lockout with a five-minute lock period.
  - Sessions have a 30-minute idle timeout and an eight-hour absolute timeout.
  - A new session ID is generated at sign-in.
  - Logout deletes the server session and clears the secure cookie.
  - Generic error responses are used without stack traces.

- **FAIL — Sign-in handling does not adequately avoid account-enumeration timing differences**
  - The sign-in condition short-circuits:
    ```ts
    email !== USER.email || password !== USER.password
    ```
  - For an invalid email, the password comparison is skipped; for the known email, it is performed.
  - While the visible error message is uniform, the implementation does not deliberately equalize credential-verification work or response timing as required.

## FAILING_ITEMS

- Normal-mode identity OTPs are generated but are neither shown to the browser UI nor logged in the browser console. The normal-mode flow therefore lacks the required simulated OTP delivery mechanism.
- TOTP verification is replayable during the valid TOTP/skew windows.
- The deterministic demo TOTP fixture (`123456`) is valid forever and can be reused indefinitely.
- Plaintext recovery codes are retained in `MfaRecord.pendingBackupCodes` until acknowledgement, rather than being encrypted or otherwise protected at rest.
- Sign-in has different processing paths for known and unknown email addresses because password comparison is skipped for a non-matching email; it does not intentionally mitigate response-timing-based enumeration.

## NEW_TASKS

1. Update `/api/signin` and `/api/identity/resend` so simulated identity OTP delivery is available in the browser for testing in every supported runtime mode: return the simulated code through the protected response/UI as appropriate and call browser `console.log` through the existing client mechanism. Keep it out of server logs, URL parameters, browser storage, and error messages.

2. Add server-side TOTP replay protection:
   - Track the accepted TOTP counter/time-step for each MFA record.
   - Reject a TOTP that has already been accepted for that counter.
   - Apply equivalent single-use and expiry behavior to the deterministic evaluation fixture, or replace it with a deterministic time-step-based fixture.

3. Replace plaintext `pendingBackupCodes` persistence with encrypted pending recovery-code storage:
   - Encrypt codes before storing them server-side.
   - Decrypt them only in authenticated, CSRF-protected endpoints that must display pending codes.
   - Remove the encrypted pending value after acknowledgement.
   - Preserve the existing PBKDF2 hashes for later one-time recovery-code verification.

4. Make sign-in credential processing timing-resistant:
   - Perform equivalent password-verification work for both known and unknown email addresses, using a dummy credential/hash path where necessary.
   - Avoid short-circuiting before password verification.
   - Retain the same generic sign-in failure response.

## DECISION

FAIL