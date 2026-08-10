## SUMMARY

The artifact is a single `app.ts` Bun HTTPS SPA with inline HTML/CSS/JavaScript and a working basic MFA demo flow. It includes several strong controls: TLS, secure cookie flags, CSP/HSTS/clickjacking headers, CSRF tokens, session rotation, account-wide invalidation, and server-side session ownership checks. However, it does not fully meet the MFA security and accessibility requirements. Most importantly, MFA secrets and recovery codes are stored in plaintext, authenticator OTPs are static and reusable, MFA verification lockout is not enforced, the QR/manual authenticator setup requirement is incomplete, and interrupted setup cannot reliably resume.

## FUNCTIONAL_CHECK

- **Single-file Bun server and SPA, no frameworks/build tools/external assets — PASS**
  - The entire server, HTML, CSS, and client JavaScript are contained in `app.ts`.
  - It uses Bun directly and standard `node:fs` only to read local TLS certificate files.
  - No bundler, framework, CDN, or external network call is used.

- **TLS / HTTPS using supplied certificates — PASS**
  - `Bun.serve` is configured with `tls: { cert: readFileSync(CERT_PATH), key: readFileSync(KEY_PATH) }`.
  - HSTS is sent through `Strict-Transport-Security`.

- **Mobile-responsive, readable SPA — PARTIAL / FAIL**
  - The layout has a mobile-friendly maximum width and responsive form controls.
  - However, it lacks a QR setup option, does not clearly distinguish primary and secondary actions, has persistent visual “Logs” clutter, and provides limited icon-supported comprehension.
  - The recovery-code view presents multiple equal-looking buttons rather than one visually prominent primary action.

- **Short plain-language instructions, examples, generous pacing, and retry support — PARTIAL / FAIL**
  - Instructions are generally short and the repeated “Take your time” hint supports untimed completion.
  - OTP fields include a six-digit placeholder example.
  - However, setup cannot be resumed correctly after refresh/interruption, recovery-code regeneration is not available in the UI, and recovery codes cannot be hidden/revealed.
  - The email input has a prefilled value but no explicit example/help text.

- **Identity OTP delivery and verification simulation — PASS**
  - The identity OTP is deterministic in demo mode (`246810`), returned to the UI, and logged in the browser as required for testing.
  - Identity OTPs are hashed server-side, expire after 20 minutes, and are marked used after successful verification.
  - Resending replaces the pending code.

- **Authenticator provisioning and manual entry support — FAIL**
  - A provisioning URI and copy button are shown.
  - No QR code is rendered.
  - The UI does not present the shared secret separately in a clear manual-entry format; users are told to copy a full `otpauth://` URI rather than being offered a clean secret value and setup details.
  - The simulated authenticator verification code is static rather than derived from the provisioning secret.

- **Backup recovery-code generation, copy, and confirmation — PARTIAL / FAIL**
  - Recovery codes are generated, displayed, copyable, and require acknowledgement before MFA becomes enabled.
  - Recovery codes can be used only once in `/api/mfa/verify`.
  - However, they are stored in plaintext, regeneration is inaccessible from the UI, and there is no hide/reveal control.

- **Internal navigation and recovery from interrupted flow — FAIL**
  - The initial flow works if completed in one browser session.
  - `/api/state` can return `"setup"` or `"backup"`, but client `begin()` handles neither correctly. It calls `start()`, which then calls `/api/authenticator/start`; that endpoint rejects an existing MFA record with a 409 response.
  - `/api/authenticator/pending` and `/api/backup/pending` exist but are not used by the client to restore progress.

- **Server-side authorization / IDOR prevention — PASS**
  - All MFA API routes except sign-in require an active server-side session.
  - The authenticated session’s `userId` is checked against the fixed account; the client does not submit a target account ID.
  - Guessed or manipulated user IDs cannot select another account’s MFA record.

- **CSRF protection on state-changing routes — PASS**
  - State-changing authenticated requests require `X-CSRF-Token` matching the server-side session token.
  - The session cookie is `SameSite=Strict`, providing additional CSRF protection.

- **Secure headers and CORS restriction — PASS**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, and cache prevention headers are present.
  - No permissive CORS response headers are sent.
  - Requests with a supplied non-local HTTPS `Origin` are rejected.

- **Secure session management — PASS**
  - Session cookies include `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - Sessions have idle and absolute expiry checks.
  - Sign-in invalidates existing account sessions and issues a new session ID.
  - Logout invalidates all sessions for the user and clears the cookie.

- **No secret/session persistence in browser storage — PASS**
  - No `localStorage`, `sessionStorage`, or non-HttpOnly cookie storage is used.
  - Secrets are held only in JavaScript memory during the active setup flow.

- **Protect OTP secrets and recovery codes at rest — FAIL**
  - `MfaRecord.secret` stores the OTP secret in plaintext.
  - `MfaRecord.backups` stores recovery codes as plaintext map keys.
  - This violates the requirement to encrypt/hash OTP secrets and backup codes at rest.

- **Use cryptographically secure generation — PARTIAL / FAIL**
  - `crypto.getRandomValues()` is correctly used.
  - However, backup code generation selects from a 30-character alphabet using `x % a.length`, introducing modulo bias.
  - More significantly, demo mode defaults to enabled and uses fixed values for the authenticator secret, OTP, and initial backup codes.

- **Authenticator OTP security: single-use and time-bound — FAIL**
  - `/api/authenticator/verify` accepts the permanent static code `135790` whenever demo mode is enabled.
  - `/api/mfa/verify` also accepts that same static code repeatedly and does not enforce a time window or one-time use.
  - This fails the requirement that verification OTPs be single-use, time-bound, and sufficiently random/secure.

- **Rate limiting and lockout of failed MFA verification — FAIL**
  - Failed identity and authenticator-enrolment attempts use `locked(session)` before checking codes.
  - `/api/mfa/verify` increments failure counts via `bad(session)` but never checks `locked(session)`.
  - A locked session can therefore continue making repeated MFA verification attempts.

- **Input validation and injection resistance — PARTIAL / FAIL**
  - OTP format validation is present and dynamic values inserted into HTML are escaped.
  - There is no database or SQL query surface.
  - Sign-in email is normalized but not validated against an email format or length limits; password and request fields also lack size limits.
  - The client relies on browser named-element globals (`f`, `re`, `copy`, `cp`, `done`, `v`, `o`) rather than explicit DOM queries, which is fragile.

- **Open redirect prevention — PASS**
  - No redirect parameter or server-side redirect behavior exists.

- **Avoid account enumeration and timing differences — PARTIAL / FAIL**
  - Sign-in returns one generic invalid-credentials message.
  - It performs a hash operation before rejection.
  - But password comparison is skipped when the email comparison fails due to `if (!equal(email, USER.email) || !equal(password, USER.password))`, leaving observable work differences between unknown-email and known-email attempts.

- **No secrets in server logs / URLs / error output — PARTIAL / FAIL**
  - The server does not log secrets or place them in URL query strings.
  - However, demo mode is enabled by default and deliberately returns static OTP values, provisioning secrets, and backup codes to the browser. Browser `console.log` is explicitly required by the deliverable for mocks, but this must be strictly development/test-only rather than the default production posture.

- **Generic errors and no verbose stack traces — PASS**
  - The top-level handler catches exceptions and returns a generic message.
  - Stack traces are not returned to clients.

## FAILING_ITEMS

- MFA OTP secrets are stored plaintext in `MfaRecord.secret`.
- Recovery codes are stored plaintext as `Map` keys in `MfaRecord.backups`.
- Authenticator verification uses a permanent deterministic code (`135790`) rather than a time-bound, single-use OTP.
- Completed MFA verification also accepts `135790` repeatedly and has no time-bound or replay protection.
- `/api/mfa/verify` does not call `locked(session)`, so lockout is not enforced after repeated failures.
- A browser refresh during authenticator setup or backup-code saving cannot resume the correct step. The client ignores `"setup"` and `"backup"` stages and invokes an endpoint that returns 409.
- QR-code provisioning is missing.
- The manual authenticator setup path is incomplete because the shared secret is not clearly displayed as an independent manual-entry value with relevant setup details.
- Backup-code regeneration exists server-side but is not exposed in the UI; hide/reveal controls are also missing.
- Demo mode is enabled by default, exposing fixed OTPs, secret material, and recovery codes in browser-visible simulation output outside an explicitly gated test mode.
- Sign-in input validation is incomplete: email format and request length limits are not enforced.
- Sign-in comparison work differs depending on whether the submitted email matches, weakening the timing-enumeration mitigation.
- Client code relies on implicit global variables created from element IDs, which is fragile and should be replaced with explicit element lookup.
- The UI does not fully satisfy the low-clutter/one-clear-primary-action and icon-supported accessibility expectations.

## NEW_TASKS

1. Replace plaintext MFA-secret storage with authenticated encryption at rest using a server-held encryption key; decrypt only when calculating/verifying an authenticator code.
2. Replace plaintext recovery-code map keys with cryptographic hashes, and verify submitted recovery codes by hash using constant-time comparison; retain only a used/not-used status associated with hashed values.
3. Implement a deterministic test-only TOTP/mock OTP mechanism that is time-bound and replay-protected, and enforce it in both enrolment verification and `/api/mfa/verify`.
4. Add `locked(session)` enforcement at the start of `/api/mfa/verify`, before any recovery-code or authenticator-code validation.
5. Make demo behavior explicitly opt-in rather than default; ensure fixed test credentials/codes and browser secret logging are available only under a dedicated evaluator/development flag.
6. Implement resume handling in `begin()` for `"setup"` and `"backup"` stages by calling `/api/authenticator/pending` and `/api/backup/pending`, then rendering the appropriate screen.
7. Add an inline, locally generated QR code for the provisioning URI without external assets or network requests.
8. Display a separate copyable manual setup secret, issuer, account label, algorithm, digits, and period alongside the QR option.
9. Add recovery-code UI controls to regenerate codes, hide/reveal codes, and copy the currently displayed code set, with plain confirmation messaging.
10. Add strict server-side request-size and field-length limits, validate sign-in email format, and perform equivalent credential comparison work for both known and unknown emails.
11. Replace implicit ID-based globals in client JavaScript with `document.querySelector`/`getElementById` references and handle clipboard API failures with a clear message.
12. Refine the UI so each screen has one visually distinct primary action, secondary actions use secondary styling, the persistent log panel is test-mode-only or collapsible, and brief icon-supported guidance is added without increasing text density.

## DECISION

**FAIL**