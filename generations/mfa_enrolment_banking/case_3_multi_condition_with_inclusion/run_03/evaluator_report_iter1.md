## SUMMARY

The artifact is a single-file Bun HTTPS SPA with a generally strong mobile-focused UI, CSP nonce usage, secure cookie attributes, CSRF checks, server-side session state, input validation, encrypted authenticator-secret storage, and hashed recovery codes. However, it does not fully meet the authentication, QR provisioning, time-based OTP, lockout, recovery-code verification, and dyslexia-support requirements. The literal security requirement against logging secrets also conflicts with the separate testing requirement to show mock secrets/codes in the browser console; the current implementation additionally exposes them in an on-page log panel.

## FUNCTIONAL_CHECK

- **FAIL — MFA endpoints enforce account-owner authorization and prevent IDOR**
  - Protected endpoints derive the user from the server-side HttpOnly session and do not accept a user ID, which prevents direct IDOR manipulation.
  - However, `/api/sign-in` accepts any syntactically valid email and any password of at least eight characters, then always assigns that requester to the fixed `account-owner-marcus` user ID. Any person can therefore access and alter the same MFA state by submitting arbitrary valid-looking credentials.

- **PASS — CSRF protection is applied to state-changing requests**
  - Sign-in requires a bootstrap CSRF token tied to an HttpOnly `mfa_boot` cookie.
  - Authenticated POST routes require `X-CSRF-Token` matching the server-side session token.
  - MFA setup, verification, recovery acknowledgement/regeneration, and logout are covered.

- **PASS — Secure HTTP headers and secure cookie attributes are present**
  - Responses include CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, and restrictive permissions policy.
  - Session and bootstrap cookies use `Secure`, `HttpOnly`, `SameSite=Strict`, and `Path=/`.
  - Responses use `Cache-Control: no-store, private`.

- **PASS — HTTPS/TLS is configured using the required certificate paths**
  - Bun is configured with `tls: { cert, key }` from `certs/cert.pem` and `certs/key.pem`.
  - The server does not provide an HTTP fallback.

- **PASS — Server-side validation and output handling are generally safe**
  - Email, password, and six-digit code formats are validated server-side.
  - No SQL database or dynamic SQL is used.
  - Client-rendered dynamic text is escaped through `esc()` before insertion into HTML.
  - Redirects are not implemented, so no open redirect is present.

- **PARTIAL/FAIL — OTPs are time-bound, single-use, sufficiently protected, and rate-limited**
  - Identity and authenticator setup codes are hashed, expire after 30 minutes, and are marked used after successful verification.
  - Failed attempts lock the *current code* after five failures.
  - The lockout is bypassable by immediately requesting a new identity code or creating new authenticator setup details, both of which replace the locked `TimedCode`. There is no account- or verification-stage-level failure counter/rate limit.
  - The authenticator verification is not a time-based OTP implementation: it verifies a separately generated random mock code rather than calculating/verifying a TOTP from the provisioned secret and time period.

- **FAIL — Mock values are deterministic as required**
  - `randomDigits()` generates new cryptographically random identity and authenticator mock codes each time.
  - `recoveryCode()` generates random recovery codes.
  - The requirements explicitly call for deterministic mock values for simulated delivery/provisioning/verification. The current values are test-visible, but not deterministic.

- **FAIL — QR provisioning is functional**
  - The displayed “QR pattern” is not an encoded QR code for the returned provisioning URI.
  - It is explicitly labelled a “Demo QR-style provisioning pattern,” so an authenticator app cannot scan it.
  - Additionally, `.qr b` has no block sizing/display rule; its empty `<b>` children may render no visible black cells at all.
  - A manual secret is displayed and can be copied, but this does not make the offered QR option functional.

- **FAIL — Recovery codes are operationally single-use**
  - Recovery codes are generated with a CSPRNG and stored as hashes, which is good.
  - There is no recovery-code verification/consumption endpoint or recovery UI. `recoveryHashes` is never used after generation.
  - Therefore, the system cannot demonstrate that recovery codes work or that each one is single-use.

- **PARTIAL/FAIL — Sensitive values are not exposed in logs**
  - The server does not log OTPs, secrets, recovery codes, or session tokens.
  - However, the client logs identity codes, authenticator secrets, authenticator confirmation codes, and recovery codes to both `console.log` and the visible `<pre id="logs">` panel.
  - This conflicts with the security requirement prohibiting secret/OTP/recovery-code logging. The requirements also separately mandate browser-console logging for test mocks, so this is a specification conflict. The on-page logs panel is not necessary to satisfy the browser-console requirement and is an avoidable exposure.

- **PARTIAL/FAIL — Dyslexia-inclusive retry, reveal, and hide controls are provided**
  - The UI is mobile responsive, spacious, plain-language, uses examples, avoids timed reading, provides copy actions, uses autocomplete attributes, and has visible current-step/progress indicators.
  - Users can request a replacement identity code and restart authenticator setup.
  - There are no controls to hide/reveal sensitive codes or secrets after showing them. The persistent on-page logs also continue displaying sensitive values.
  - The “Need a hint?” control uses a blocking `alert()`, rather than an accessible in-page hint.

- **PASS — Primary flow interactions and internal navigation work**
  - Sign-in, identity-code request/verification, setup, authenticator-code verification, recovery-code display/regeneration, acknowledgement, completion, and logout are wired through fetch requests.
  - There are no broken internal hyperlinks; navigation is state-based within the SPA.

- **PASS — Single-file and zero-compilation compliance**
  - The supplied application is contained in one `app.ts` file.
  - It uses Bun, regular HTML, inline CSS, and vanilla browser JavaScript.
  - It uses no framework, bundler, compiler, external asset, or external network call.

- **PASS — Production-safe unexpected error handling**
  - The top-level request handler returns a generic 500 response without a stack trace.
  - API error messages are specific enough to help users correct expected input errors.

## FAILING_ITEMS

- `/api/sign-in` does not authenticate a distinct account owner. Any valid-looking email/password gains the fixed `account-owner-marcus` account and its MFA state.
- Rate limiting/lockout is attached only to a particular generated code and is bypassed by requesting a new identity code or regenerating authenticator setup.
- Authenticator verification is a random-code check, not a time-based OTP verification derived from the provisioned secret.
- Mock OTP/recovery values are random rather than deterministic, contrary to the simulation requirement.
- The QR display is a non-scannable decorative pattern, not a QR code containing the `otpauth://` URI. Its black modules may also not render due to empty inline `<b>` elements.
- Recovery codes are generated and hashed but never accepted, checked, consumed, or invalidated through a recovery verification flow.
- The UI does not provide hide/reveal controls for shown secrets and codes.
- Sensitive mock values are unnecessarily exposed in the visible on-page logs panel. Browser-console logging is required by the testing deliverable but conflicts with the literal “never expose in logs” security requirement; this conflict must be explicitly resolved.
- The help interaction is a browser alert rather than a predictable accessible in-page help/hint region.

## NEW_TASKS

1. Replace the fixed-user sign-in behavior with a server-side mock account store that validates credentials and maps each authenticated session to its own account; do not allow arbitrary credentials to access Marcus’s account or overwrite its email/MFA state.

2. Add verification-stage/account-level failed-attempt tracking and lockout/rate limiting that persists when a user requests a replacement identity code or restarts authenticator setup.

3. Implement actual 30-second TOTP generation/verification from the provisioned shared secret, or explicitly implement a documented deterministic test-mode authenticator fixture that still satisfies the required verification behavior.

4. Replace random test mock values with deterministic fixture values as required, while clearly separating test simulation behavior from any production-strength generation path required by the security requirements.

5. Replace `drawQr()` with a standards-compliant, scannable QR-code encoder for the returned `otpauth://` provisioning URI; retain the copyable/manual secret fallback.

6. Add a protected recovery-code verification endpoint and UI flow that hashes submitted codes, checks membership, atomically consumes the matching code, and rejects reuse.

7. Add explicit hide/reveal controls for identity codes, authenticator secrets, and recovery codes, with hidden-by-default behavior after the user proceeds where practical.

8. Remove the visible on-page mock-secret log panel. Resolve the conflicting browser-console testing requirement versus the no-secret-logging security requirement through an explicit test-only policy or requirement clarification.

9. Replace blocking `alert()` help with an in-page accessible hint/status region that can be opened and dismissed without interrupting the user.

## DECISION

FAIL