## SUMMARY

The artifact is structurally close to the requested single-file Bun MFA application and includes substantial server-side security logic. However, it has a critical CSP nonce handling defect: the final response headers overwrite the page CSP using a different nonce than the nonce embedded in the inline `<style>` and `<script>` tags. Browsers will block both the client script and styles, leaving the SPA non-functional. It also logs the authenticator provisioning secret in the browser console, contrary to the requirement not to expose OTP seeds in logs.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no frameworks, build tools, or external assets**
  - All server logic, HTML, CSS, and browser JavaScript are contained in `app.ts`.
  - It imports only Bun’s built-in server API and does not require bundling or compilation.
  - TLS certificates are loaded from the required `certs/cert.pem` and `certs/key.pem` paths.

- **FAIL — SPA UI and browser interactivity work directly when served**
  - `pageResponse()` generates an HTML nonce and applies it to the inline `<style>` and `<script>`.
  - However, after `pageResponse()` returns, `fetch()` calls `issueHeaders(request, response)`.
  - `issueHeaders()` replaces the existing `Content-Security-Policy` with a new CSP containing a newly generated nonce.
  - The nonce in the delivered CSP therefore does not match the nonce in the delivered `<script>` or `<style>` tags.
  - The browser will block the inline JavaScript, so the MFA UI cannot bind event handlers or make API calls. Inline styles will also be blocked.

- **FAIL — Responsive, legible mobile web UI**
  - The markup and CSS are appropriately designed for a narrow mobile viewport.
  - In actual browser execution, the CSS is blocked by the CSP nonce mismatch, so the intended responsive styling is not applied.

- **FAIL — Enrolment, authenticator verification, backup-code display, recovery, regeneration, and logout flows function**
  - The server endpoints and client flow logic are largely implemented.
  - Because the browser blocks the inline client script under the delivered CSP, no buttons, forms, state transitions, or API calls work in practice.

- **PASS — Server-side authorization and IDOR protections**
  - Protected MFA endpoints derive the user only from an HttpOnly session cookie through `authorized()`.
  - No client-supplied user ID is accepted for MFA settings, provisioning, activation, recovery-code operations, or logout.
  - Manipulated or guessed identifiers cannot select another user’s MFA settings.

- **PASS — CSRF protections on authenticated state-changing MFA actions**
  - Authenticated state-changing endpoints require a valid per-session CSRF token.
  - This includes identity verification, provisioning, authenticator verification, MFA activation, backup-code regeneration, recovery-code consumption, and logout.
  - The session cookie is set with `SameSite=Strict`.

- **FAIL — Secure headers are correctly configured without breaking the enrolment page**
  - HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, cache prevention, and CSP are present.
  - However, the final CSP is invalid for the rendered document because it contains a different script/style nonce than the HTML. This security configuration breaks the page instead of safely allowing its own trusted inline resources.

- **PASS — TLS and secure cookies**
  - The primary application is served over TLS and requires the stated certificate files.
  - The HTTP listener redirects to HTTPS rather than serving application content.
  - Session cookies use `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, and a bounded max age.

- **PASS — Secure session lifecycle**
  - A new session is generated at sign-in.
  - The session ID is rotated after successful identity verification.
  - Idle and absolute session timeouts are checked on protected requests.
  - Logout deletes the server-side session and expires the cookie.

- **PASS — OTP, recovery-code, and verification controls**
  - TOTP secrets are generated using `crypto.getRandomValues`.
  - TOTP values are generated with HMAC-SHA-256 and a 30-second moving counter.
  - Enrollment OTPs cannot be replayed in the same time counter.
  - Identity codes are time-bound and single-use.
  - Backup recovery codes are generated with a cryptographic RNG, stored as salted hashes, and marked used after successful recovery.
  - Identity, authenticator, and recovery verification have failure counters and five-minute lockouts.

- **PASS — Input validation, output encoding, and redirect controls**
  - The server validates email, phone, OTP, recovery-code, and CSRF formats.
  - Redirect inputs are limited to an internal allow-list.
  - UI-rendered dynamic values are escaped with `esc()` before insertion into `innerHTML`.
  - No SQL/database interpolation exists in this in-memory implementation.

- **FAIL — Secrets are not exposed in logs**
  - The browser client explicitly logs the provisioning secret:
    - `Simulated authenticator provisioning key delivered: ...`
    - `Simulated replacement authenticator provisioning key delivered: ...`
  - The requirements explicitly prohibit exposing OTP shared seeds in logs.
  - The secret may be shown in the UI because manual authenticator enrollment requires it, but it should not be written to `console.log` or the on-page logs panel.

- **PASS — Mock values are deterministic/testable and available through the UI**
  - The identity code, provisioning secret, current TOTP value, and backup codes are returned in simulated API responses and shown through the UI flow.
  - Manual secret submission is supported for authenticator verification, as required.
  - Note: this functionality is currently unreachable in the browser until the CSP issue is fixed.

## FAILING_ITEMS

- The page-level CSP is overwritten in `issueHeaders()` with a new nonce that differs from the nonce generated by `pageResponse()` and embedded into the HTML.
  - Result: browsers block the inline `<script>` and `<style>`.
  - Result: the SPA cannot run, the mobile UI is unstyled, and all enrolment actions fail.

- The browser client logs the authenticator provisioning secret/OTP seed through `console.log()` and mirrors it in the on-page logs panel.
  - This violates the requirement not to expose OTP seeds in logs.
  - The provisioning secret should remain visible only in the manual setup UI where it is necessary for enrollment.

## NEW_TASKS

1. Fix CSP handling so the final response CSP uses the same nonce as the inline script and style tags generated for the HTML page.
   - Prefer preserving the CSP already set by `pageResponse()` in `issueHeaders()` rather than overwriting it.
   - Alternatively, pass the page nonce into `issueHeaders()` and use that exact nonce.
   - Verify that the delivered CSP permits the page’s inline `<style nonce="...">` and `<script nonce="...">`.

2. Remove provisioning-secret logging from the browser client.
   - Delete the `log()` calls that include `provision.secret`.
   - Do not include the setup secret in the on-page logs panel.
   - Continue displaying the manual setup secret in the setup form/UI, since manual secret enrollment is required.
   - Retain only the mock OTP and backup-code console/UI logging required for evaluation.

## DECISION

**FAIL**