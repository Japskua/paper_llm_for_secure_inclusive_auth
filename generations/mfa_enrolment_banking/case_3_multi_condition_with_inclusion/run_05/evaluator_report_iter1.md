## SUMMARY

The artifact is a single-file Bun application with a generally strong structure: HTTPS setup, session cookies, CSRF checks, server-side account ownership, secure headers, input validation, mobile-responsive UI, and a usable simulated MFA flow are present. However, it does not fully meet the requirements because the displayed “QR code” is not a valid scannable QR code, failed form submissions remove the user’s ability to retry, recovery-code attempts are not rate-limited, sensitive test values are rendered into an on-page log, and the provisioning secret is temporarily stored in plaintext server memory.

## FUNCTIONAL_CHECK

- **Single-file Bun app with inline HTML, CSS, client JavaScript, and Bun server: PASS**
  - The entire implementation is contained in `app.ts`.
  - It uses Bun’s built-in `serve`, reads TLS material from `certs/cert.pem` and `certs/key.pem`, and does not use external assets, frameworks, bundlers, or build tools.

- **HTTPS/TLS and secure response headers: PASS**
  - The server is configured with TLS.
  - Responses include CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, and no-store cache controls.
  - Errors are generic and do not expose stack traces.

- **Secure session management: PASS**
  - Session cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - Sessions have idle and absolute expiration handling.
  - A new session ID is generated at sign-in.
  - Logout invalidates the server-side session and clears the cookie.

- **Server-side authorization / IDOR prevention: PASS**
  - Authenticated API actions derive the account only from the authenticated server-side session.
  - No client-supplied account or user identifier is accepted for MFA state changes.
  - This prevents manipulated account IDs from being used to access another account’s MFA state.

- **CSRF protection for state-changing authenticated requests: PASS**
  - Authenticated `POST` endpoints require a server-issued CSRF token.
  - The token is sent through the `X-CSRF-Token` header and checked server-side.

- **Input validation and output safety: PASS**
  - JSON request bodies are size limited and parsed safely.
  - Email, OTP, and recovery-code formats are validated server-side.
  - UI content is predominantly inserted through `textContent`, rather than unsafe HTML injection APIs.
  - No SQL/database query layer exists, so parameterized-query requirements are not applicable to this mock implementation.

- **Identity and authenticator verification flow: PASS**
  - Identity and authenticator codes are deterministic simulated values.
  - Codes are time-bound, single-use, and lock after five incorrect attempts.
  - Test OTP values are returned to the UI flow and written with browser-side `console.log`, as required for testing.

- **Recovery-code verification rate limiting and lockout: FAIL**
  - `/api/recovery/use` has no failed-attempt counter, rate limit, or lockout.
  - An attacker with a valid session and CSRF token can repeatedly submit recovery-code guesses without being locked out.
  - This does not meet the requirement to rate-limit and lock out repeated failed verification attempts.

- **OTP shared-secret protection at rest: FAIL**
  - `/api/provision` stores `account.provisioningSecret = secret` in plaintext.
  - The secret is only encrypted after authenticator activation succeeds.
  - The OTP shared secret should be encrypted immediately when generated, including while setup is pending.

- **QR-code provisioning option: FAIL**
  - The `qr()` function draws a deterministic pseudo-random grid and finder-like squares, but it does not generate a valid QR code encoding the `otpauth://` URI.
  - An authenticator app cannot scan this image.
  - The UI claims the user can “Scan the square code first,” but scanning will not work.

- **Manual provisioning fallback: PASS**
  - The setup secret is displayed and can be copied.
  - A manual setup key field is available.
  - The authenticator activation endpoint validates the submitted manual key against the active provisioning secret.

- **Dyslexia-friendly / mobile UX: FAIL**
  - The layout, spacing, text size, plain language, icons, examples, copy buttons, and mobile card design are generally good.
  - However, retry behavior is broken after a failed form submission. The shared `failure(form, err)` implementation uses `form.replaceChildren(...)`, removing the inputs and submit button.
  - For example, entering a wrong identity code leaves the user unable to correct and resubmit the code without navigating away. This conflicts with the requirement that users can retry steps without penalty.

- **No sensitive values in logs or exposed diagnostics: FAIL**
  - The requirements explicitly require browser `console.log` for deterministic test OTPs and recovery codes, which the implementation does.
  - However, the app additionally renders these sensitive values in the visible in-page “Logs” panel. For example, identity OTPs, authenticator OTPs, and all recovery codes are appended to `#logs`.
  - This unnecessarily exposes secrets in the page UI and conflicts with the security requirement not to expose OTPs or backup codes in logs. Browser-console-only test logging is the least-exposure interpretation of the testing requirement.

- **Internal navigation and completion flow: PASS**
  - The sign-in, identity, authenticator, recovery-code, settings, recovery-code-use, regeneration, and logout paths are implemented through functioning client-side navigation and API calls.

## FAILING_ITEMS

- The displayed authenticator “QR code” is not a real QR encoding of the provisioning URI, so it cannot be scanned by authenticator applications.
- Failed form submissions call `failure(form, err)`, which replaces all form controls with an error message and prevents retrying the same step.
- Recovery-code verification lacks failed-attempt tracking, throttling, or lockout.
- `account.provisioningSecret` is stored as plaintext after provisioning begins and before authenticator activation completes.
- The visible on-page simulation log renders test OTPs and full backup recovery codes, creating unnecessary sensitive-value exposure beyond the required browser-console simulation output.

## NEW_TASKS

1. Replace the custom pseudo-QR canvas renderer with a real, dependency-free QR encoder that correctly encodes the generated `otpauth://totp/...` provisioning URI; retain the manual secret and copy fallback.

2. Refactor client-side error handling so form errors are shown in a dedicated error/notice element without deleting inputs, buttons, entered values, or submit handlers; ensure every failed sign-in, identity, authenticator, recovery confirmation, and recovery-code submission can be corrected and retried.

3. Add server-side failed-attempt tracking and a timed lockout or rate limit for `/api/recovery/use`, with a clear generic error message that explains when the user may retry.

4. Encrypt the authenticator provisioning secret as soon as it is generated. Store only encrypted pending-secret material in the account state, decrypt it only when needed for activation validation, and delete it after successful activation or replacement.

5. Remove the visible `#logs` simulation panel and all DOM rendering of OTPs/recovery codes into that panel. Keep the required deterministic test values in browser `console.log`, while continuing to show recovery codes in the dedicated recovery-code screen where the user is expected to save them.

## DECISION

FAIL