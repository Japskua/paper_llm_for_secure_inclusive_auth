## SUMMARY

The artifact is a single-file Bun HTTPS SPA with a largely complete MFA enrolment flow, server-side session ownership checks, CSRF tokens, encrypted OTP-secret storage, hashed recovery codes, rate limiting, and an accessible mobile-oriented UI. However, it does not fully meet the requirements because the embedded QR encoder is technically invalid, production security is weakened by permanently enabled predictable test values, the trusted-origin policy is too broad, and sensitive mock values are rendered in an on-screen log panel.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no external assets or build tooling**
  - The server, HTML, CSS, and browser JavaScript are all contained in `app.ts`.
  - It uses `Bun.serve`, serves the page directly, and does not use frameworks, bundlers, external scripts, or network assets.

- **PASS — HTTPS/TLS server configuration**
  - Bun is configured with `certs/cert.pem` and `certs/key.pem`.
  - The session cookie is marked `Secure`, and HSTS is sent.

- **FAIL — QR-code authenticator provisioning works**
  - The QR implementation is not a valid QR Version 8-L encoder.
  - The BCH generation for format and version information is incorrect: the code attempts BCH division on unshifted values, so it never performs the required polynomial division.
  - The QR data/ECC block parameters are also inconsistent with QR Version 8-L capacity. This can produce an unscannable QR code.
  - Manual secret and provisioning URI copy options exist, but the required QR option itself is faulty.

- **PASS — Manual authenticator setup is supported**
  - The Base32 secret and `otpauth://` provisioning URI can be revealed and copied.
  - A user can use the manual secret in an authenticator app and submit the resulting six-digit code.

- **PASS — MFA flow and internal navigation/state flow**
  - The flow covers sign-in, identity check, authenticator provisioning, OTP verification, recovery code handling, completion, recovery-code testing, and logout.
  - The state machine prevents most out-of-order requests through server-side `stage` checks.
  - Page refresh handling intentionally requests fresh provisioning details rather than persisting OTP secrets in browser storage.

- **PASS — Dyslexia-conscious mobile UX**
  - The UI is responsive, has generous spacing, short instructions, examples, clear progress indication, visible primary actions, copy controls, reveal/hide controls, and no animations or reading countdowns.
  - Inputs use relevant browser autofill values, including `autocomplete="one-time-code"` and telephone/email/password autocomplete.
  - Error messages are plain-language and describe a corrective action.

- **FAIL — Predictable test credentials/codes do not meet cryptographic and authentication requirements**
  - `TEST_MODE` is permanently `true`.
  - The identity verification code is always `246810`.
  - Recovery codes are always the same static list.
  - This violates the requirements that verification codes and recovery codes use cryptographically secure randomness and sufficient entropy.
  - It also makes the claim that an earlier identity code “no longer works” incorrect: after resend, the replacement code has the same value (`246810`), so entering the prior value still verifies the newly issued code record.

- **PASS — OTP secret and recovery-code storage protections**
  - OTP secrets are encrypted at rest using AES-GCM.
  - Recovery codes are stored as PBKDF2-SHA-256 hashes with per-code salts.
  - OTP secrets, recovery code hashes, session IDs, and CSRF tokens are not stored in `localStorage`, `sessionStorage`, or readable cookies.

- **PASS — OTP/recovery-code expiry, single-use behavior, and lockout**
  - Authenticator provisioning has an expiry.
  - OTP success advances the flow and cannot be repeated at the prior stage.
  - Recovery codes have one-use state and expiry.
  - Failed OTP/recovery attempts are rate-limited with a five-minute lockout after five failures.

- **PASS — Server-side ownership enforcement / IDOR resistance**
  - API operations use the session cookie and do not accept account or user IDs from the client.
  - Request bodies explicitly reject `userId` and `accountId`.
  - Authenticated endpoints use `owner(req)` and therefore operate only on the current authenticated session.

- **PASS — CSRF protection on state-changing operations**
  - State-changing requests require an `X-CSRF-Token` matching the session token.
  - The session cookie uses `SameSite=Strict`.
  - Sign-in, identity verification/resend, authenticator setup/refresh, OTP verification, recovery generation/completion/verification, and logout require CSRF validation.

- **FAIL — CORS/trusted-origin restriction is too broad**
  - `trusted()` accepts any HTTPS port on `localhost`, `127.0.0.1`, or `[::1]`:
    ```ts
    /^https:\/\/(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/
    ```
  - This is not a strict allow-list of the application’s own origin. Any service running on another local HTTPS port is treated as trusted.
  - The allowed origin must be restricted to the specific deployed application origin(s), such as `https://localhost:3000`.

- **PASS — Secure response headers are present**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, `Cache-Control: no-store`, and a restrictive `Permissions-Policy` are set.
  - Generic server errors are returned without stack traces.

- **FAIL — CSP is internally inconsistent with the HTML**
  - The CSP does not permit inline style attributes:
    ```html
    <span id="pb" style="width:16%"></span>
    ```
  - Because `style-src` only permits the nonce-bearing stylesheet, the browser can block this inline `style` attribute.
  - The progress width is later set via JavaScript, but the initial inline style is non-compliant and should be replaced with a CSS class or initialized exclusively through JavaScript.

- **FAIL — Sensitive values are exposed in an on-screen “Logs” panel**
  - The UI renders a persistent visible log panel and writes mock OTPs and recovery codes into it:
    ```js
    logs.textContent = ...
    ```
  - This increases visual clutter and exposes security-sensitive values unnecessarily in the page.
  - The requirements specifically prohibit exposing OTPs and backup codes in logs. Browser-console mock output is requested for testing, but an on-screen debug log panel is not necessary and conflicts with both the security and low-clutter UX requirements.

- **PASS — Input validation and output handling**
  - Server-side fields have type checks, maximum lengths, format validation, and stage validation.
  - The app does not use a database, so SQL injection is not applicable.
  - Dynamic sensitive values are assigned with `textContent` rather than inserted as raw HTML in the relevant secret/code display paths.
  - No redirect parameter is accepted, so no open redirect is present.

## FAILING_ITEMS

- The QR-code generator is invalid and may not be scanned by authenticator applications.
- `TEST_MODE` is always enabled, making identity and recovery codes predictable and non-random in the running application.
- Identity-code resend does not actually make the previous code value unusable because every issued code is `246810`.
- Trusted-origin validation allows arbitrary HTTPS ports on localhost addresses rather than an exact allow-list of application origins.
- The visible Logs panel displays mock OTPs and recovery codes, conflicting with sensitive-data logging restrictions and the requirement to avoid visual clutter.
- The CSP blocks the page’s inline `style="width:16%"` attribute, making the document inconsistent with its own policy.

## NEW_TASKS

1. Replace the custom QR implementation with a verified, standards-compliant in-file QR encoder, or correct its Version 8-L capacity, block layout, Reed-Solomon ECC, format BCH bits, version BCH bits, masking, and remainder-bit handling; verify that the generated `otpauth://` URI scans successfully in an authenticator app.

2. Make secure production behavior the default: disable `TEST_MODE` by default and generate identity codes and recovery codes using cryptographically secure randomness.

3. If deterministic browser-console mocks are retained for evaluation, isolate them behind an explicit non-production test configuration that cannot be enabled in normal deployment; ensure each resent identity code has a distinct value.

4. Replace the regex-based localhost-any-port trust check with an exact origin allow-list for the actual application origin(s), including the expected port.

5. Remove the visible on-page Logs panel and stop rendering OTPs or recovery codes as debug logs in the DOM; retain only the explicitly required browser `console.log` mock output in test mode.

6. Remove the inline progress-bar style attribute and set its initial width through a nonce-authorized stylesheet class or through JavaScript after page load.

## DECISION

**FAIL**