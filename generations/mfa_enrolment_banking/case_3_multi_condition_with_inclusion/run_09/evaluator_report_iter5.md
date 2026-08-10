## SUMMARY

The artifact is a single `app.ts` Bun HTTPS application with a functional staged MFA flow, secure session cookies, CSRF checks, server-side stage/ownership controls, encrypted OTP secrets, hashed recovery codes, input validation, and a responsive mobile UI. However, it does not fully meet the requirements: the claimed QR encoder produces non-compliant QR matrices because it masks functional modules, mock values are not deterministic, and sensitive mock values are deliberately displayed in an on-page log panel. The required comments mapping implementation sections to requirements are also insufficient.

## FUNCTIONAL_CHECK

- **Single-file Bun server with inline HTML, CSS, and vanilla browser JavaScript: PASS**
  - The full server and client application are contained in `app.ts`.
  - It uses `Bun.serve` directly and does not require a framework, bundler, compiler step, or external assets.

- **HTTPS/TLS using `certs/cert.pem` and `certs/key.pem`: PASS**
  - `Bun.serve` is configured with:
    - `cert: Bun.file("certs/cert.pem")`
    - `key: Bun.file("certs/key.pem")`
  - The application is served as HTTPS and also supplies HSTS.

- **Responsive, mobile-oriented MFA enrolment SPA: PASS**
  - The UI has a narrow mobile shell, responsive sizing, touch-sized controls, readable input fields, and mobile-friendly viewport configuration.
  - The staged flow works through sign-in, identity verification, authenticator setup, OTP verification, recovery-code saving, completion, recovery-code test, and logout.

- **Dyslexia-friendly and inclusive UX: PASS**
  - Instructions are generally short and plain.
  - The interface uses adequate spacing, readable sizing, icons paired with steps, examples for expected input, `autocomplete` attributes, `inputmode="numeric"`, copy actions, reveal/hide controls, and no moving or flashing UI.
  - The user can resend identity codes, refresh authenticator details, regenerate recovery codes, reveal/hide secrets, and retry failed steps.

- **Authenticator provisioning supports QR and manual entry: FAIL**
  - Manual secret and provisioning-URI reveal/copy options are implemented.
  - However, the QR encoder is not standards-compliant. In `qrMatrix`, after data placement, functional modules are no longer distinguished from data modules. The masking loop then applies masks to alignment patterns and other reserved/function modules:
    ```js
    if(a[r][c]!==null && ... ) a[r][c]=a[r][c]^masks[mask](r,c);
    ```
  - QR masks may only be applied to data modules. Masking alignment patterns corrupts the generated QR code and can make it unscannable.

- **Mock OTP and recovery values are available to the browser and browser console: PARTIAL / FAIL**
  - Identity codes, TOTP test codes, and recovery codes are returned from the server response and emitted by the browser with `console.log`, as required for testing.
  - However, they are generated randomly and time-dependently rather than being deterministic mock values. For example:
    - Identity codes use `randomSixDigits()`.
    - Authenticator secrets use cryptographic randomness and TOTP changes by time window.
    - Recovery codes use `crypto.getRandomValues`.
  - The requirement explicitly calls for deterministic mock values while preserving working verification.

- **No sensitive values in logs or error output: FAIL**
  - The server appropriately avoids logging secrets and codes.
  - However, the client renders a persistent on-page `Logs` section and writes OTPs and recovery codes into it:
    ```js
    logs.textContent += "\n" + x;
    ```
  - This exposes identity codes, authenticator OTPs, and recovery codes in a visible UI log, contrary to the security requirement not to expose OTPs, seeds, or backup codes in logs. Browser-console mock logging is specifically requested for testing, but the additional on-page log sink is not necessary and broadens exposure.

- **Broken access control protections: PASS**
  - MFA modification and state endpoints use `owner(req)`, which requires an authenticated server-side session.
  - User/account identifiers supplied in JSON bodies are rejected.
  - The session determines the account owner; user-controlled IDs are not used for lookup.
  - Stage checks prevent skipping enrolment steps.
  - State-changing requests require a CSRF token.

- **CSRF and cookie protections: PASS**
  - State-changing API calls check `X-CSRF-Token`.
  - Session cookies are set with `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - Session IDs are regenerated on successful sign-in, mitigating session fixation.
  - Logout invalidates the server session and clears the cookie.

- **Security headers and CORS restrictions: PASS**
  - CSP with nonces, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, no-store caching, and a restrictive permissions policy are present.
  - CORS preflight handling is restricted through `trusted(req)` and does not permit arbitrary origins.

- **Cryptographic protections at rest and secure generation: PASS**
  - OTP secrets are encrypted using AES-GCM.
  - Identity codes are HMAC-protected.
  - Recovery codes are PBKDF2-hashed with per-code salts.
  - Cryptographic random generation is used for session IDs, CSRF values, encryption IVs, OTP secrets, recovery codes, and identity codes.
  - Secrets are not persisted in browser storage or non-HttpOnly cookies.

- **Input validation and XSS/injection protections: PASS**
  - JSON request bodies are parsed and type-checked.
  - User/account/redirect fields are rejected.
  - Email, phone number, OTP, and recovery-code formats are validated server-side.
  - The UI does not inject user-controlled strings into `innerHTML`; its interpolated values are constrained server-generated values.
  - There is no database layer, so parameterised-query requirements are not applicable to this in-memory mock implementation.

- **OTP/recovery verification, single use, expiry, and lockout: PASS**
  - Identity codes expire and are marked used.
  - TOTP confirmation is only accepted once per provisioned secret through `otpUsed`.
  - Recovery codes are marked used after verification and expire after the configured lifetime.
  - Failed identity, OTP, and recovery verification attempts lock the session for five minutes after repeated failures.
  - Sessions have idle and absolute expiration.

- **Internal navigation and workflow continuity: PASS**
  - The app is a state-driven SPA and does not contain broken internal links.
  - Page refresh behavior is handled: OTP setup details can be regenerated, recovery codes can be regenerated, and state is reloaded from the server.

- **Clear comments mapping implementation to requirement sections: FAIL**
  - The file contains a broad introductory comment and a QR-specific comment, but it does not provide clear section-level comments mapping authorization, CSRF, session handling, headers, cryptography, input validation, and lockout behavior back to Requirements 1–5 as requested.

## FAILING_ITEMS

- The QR-code generator masks functional QR modules, including alignment patterns, because it does not retain a function-module map after data placement. The resulting QR image is not reliably scannable or standards-compliant.
- Test identity codes, authenticator values, and recovery codes are random/time-based rather than deterministic mock values required by the specification.
- Sensitive codes are copied into an on-page persistent “Logs” panel, exposing OTPs and recovery codes beyond the required browser-console test output.
- The source lacks clear implementation comments that map major code sections to the stated security requirement categories.

## NEW_TASKS

1. Replace or correct `qrMatrix` so it follows ISO/IEC 18004 behavior: retain a dedicated function-module map, apply masks only to data modules, write format/version information to correct reserved coordinates, and verify the generated provisioning QR code scans successfully with a standard authenticator/QR decoder.

2. Implement deterministic test-mode mock values for identity verification, authenticator verification, and recovery codes while retaining server-side verification behavior and avoiding time-dependent test failures.

3. Remove the visible `Logs` panel and its DOM logging behavior for identity codes, OTPs, secrets, and recovery codes. Keep only the browser `console.log` output explicitly required for mock testing, and ensure ordinary UI notices/errors never disclose sensitive values.

4. Add concise section comments identifying where Requirements 1–5 are implemented, including access control/CSRF, headers/CORS/cookies, cryptographic storage/TLS, validation/output handling, and authentication/session/rate-limit logic.

## DECISION

FAIL