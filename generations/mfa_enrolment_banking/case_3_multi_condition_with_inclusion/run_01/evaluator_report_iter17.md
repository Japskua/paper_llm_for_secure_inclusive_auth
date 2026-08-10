## SUMMARY

The artifact is a single-file Bun HTTPS SPA with substantial security and accessibility work: authenticated server-side sessions, CSRF checks, security headers, encrypted OTP secrets, hashed recovery codes, rate limiting, responsive mobile UI, and browser-side interaction. However, it does not fully meet the requirements because the locally generated QR code is not standards-compliant and therefore cannot reliably provision an authenticator. The deterministic mock-code console logging requirement is also only available behind an undocumented environment flag rather than in the normal supplied run flow.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun server and SPA delivery**
  - The server, HTML, CSS, and browser JavaScript are contained in `app.ts`.
  - It uses `Bun.serve()` directly, with no framework, bundler, compiler, or external assets.

- **PASS — HTTPS/TLS usage**
  - The Bun server is configured with `certs/cert.pem` and `certs/key.pem`.
  - Requests are restricted to HTTPS localhost origins and HSTS is sent.

- **PASS — Mobile and dyslexia-friendly UI**
  - The layout has a mobile viewport meta tag, responsive width constraints, generous spacing, readable font sizing, clear labels, examples for expected formats, no animations, and visible primary actions.
  - Help is consistently present and wording is generally short and plain.

- **PASS — Sign-in, MFA enrolment, OTP verification, backup-code generation, recovery-code verification, replacement, regeneration, and logout flows**
  - The UI flows are connected through functioning browser-side handlers and server endpoints.
  - OTP setup can be requested again, secrets can be revealed/hidden, recovery codes can be copied, recovery codes are single-use, and logout invalidates the server session.

- **FAIL — QR-code authenticator provisioning is valid and usable**
  - The custom QR encoder is not standards-compliant for QR Version 10.
  - QR Version 10 byte mode requires a 16-bit character-count field, but the implementation writes only one count byte via:
    - `const payload=[0x40,bytes.length,...bytes];`
  - Version 10 QR codes also require version-information modules, but the matrix implementation does not reserve or write Version 10 version information.
  - This causes the module/data layout to diverge from the QR specification. A scanner may fail to read the QR code or decode an incorrect provisioning URI.
  - Since QR provisioning is explicitly offered, it must work reliably.

- **PASS — Manual alternative to QR provisioning**
  - The authenticated user can reveal and copy the TOTP secret, and can view the full `otpauth://` URI.
  - This provides an alternative to scanning the QR image.

- **FAIL — Deterministic mock values are available through the required normal browser-console testing flow**
  - OTP test values and recovery-code console output are only emitted if `MFA_TEST_MOCK_LOGGING=1`.
  - The provided normal startup instruction is `bun app.ts`; it does not enable this mode or document the required environment variable.
  - In the normal flow, `/api/provision` does not return `verificationCode`, and the browser does not log it.
  - The requirement explicitly calls for mocks through browser `console.log` and says OTP and backup recovery codes must be returned to the UI/testing flow and shown there.

- **PASS — Broken access control protections**
  - MFA endpoints obtain the account identity exclusively from the authenticated server-side session.
  - There is no client-supplied account/user ID accepted by MFA endpoints, preventing straightforward IDOR manipulation.
  - State-changing MFA routes require an authenticated session plus same-origin and CSRF-token validation.

- **PASS — CSRF and session-cookie protections**
  - The session cookie is `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - MFA state-changing routes require `Origin` validation and `X-CSRF-Token`.
  - Session IDs are rotated on successful authentication and invalidated on logout.

- **PASS — Security response headers and CORS restriction**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, restrictive referrer policy, and no-store caching are configured.
  - CORS is only emitted for the trusted same-origin HTTPS localhost origin.

- **PASS — Secret generation and storage protections**
  - TOTP secrets and recovery codes use cryptographically secure random generation.
  - Pending/active OTP secrets are AES-GCM encrypted in the server-side account object.
  - Recovery codes are stored as HMAC values rather than plaintext.
  - No secrets or sessions are placed in localStorage, sessionStorage, or non-HttpOnly cookies.

- **PASS — Input validation and output encoding**
  - Email, password, OTP, and recovery-code formats are validated server-side.
  - Dynamic client-rendered values are escaped before insertion into HTML.
  - No user-controlled redirect target is accepted.

- **PASS — OTP/recovery-code replay prevention and rate limiting**
  - OTP counters are tracked as used, preventing reuse of a successfully verified TOTP time step.
  - Recovery codes are removed when used.
  - Both OTP and recovery-code failures have a five-attempt lockout mechanism.

- **FAIL — Lockout state does not reset cleanly after the lockout period**
  - `otpFailures` and `recoveryFailures` are not reset when `otpLocked` or `recoveryLocked` expires.
  - After a user waits out a lockout, one subsequent invalid attempt immediately creates another lockout because the failure counter is still at or above `MAX_FAILURES`.
  - This conflicts with the requirement to let users retry without penalty and creates an unnecessarily punitive retry experience.

## FAILING_ITEMS

- The QR generator does not correctly encode Version 10 QR byte-mode payloads:
  - It uses an 8-bit length field where Version 10 requires a 16-bit byte-mode character count.
  - It does not reserve/write required Version 10 version-information modules.
  - The offered QR provisioning path is therefore not reliable.

- Browser-console mock output for OTPs and recovery codes is disabled by default and depends on an undocumented `MFA_TEST_MOCK_LOGGING=1` environment variable.
  - The normal `bun app.ts` run path does not provide the required deterministic test OTP in the browser console/UI flow.

- OTP and recovery-code failed-attempt counters remain at the lockout threshold after lockout expiry.
  - One failed retry after waiting can immediately trigger another lockout rather than starting a fresh attempt window.

## NEW_TASKS

1. Replace or repair the QR encoder so it generates a standards-compliant QR code for the exact `otpauth://` URI, including correct Version 10 byte-mode character-count encoding, reserved version-information regions, version-information bits, correct data placement, error correction, and masking.

2. Add a reproducible, documented testing mode to the normal application startup flow that returns the deterministic current mock TOTP and generated recovery codes to the authenticated browser UI response and logs them with browser-side `console.log`, while keeping this behavior disabled in production mode.

3. Reset `otpFailures` when an expired OTP lockout is detected before processing a new verification attempt.

4. Reset `recoveryFailures` when an expired recovery-code lockout is detected before processing a new recovery-code attempt.

## DECISION

FAIL