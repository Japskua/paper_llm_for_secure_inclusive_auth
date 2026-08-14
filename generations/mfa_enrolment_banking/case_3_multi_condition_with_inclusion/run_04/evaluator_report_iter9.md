## SUMMARY

The artifact is a single `app.ts` Bun TLS server with inline HTML, CSS, and vanilla browser JavaScript. It implements most of the MFA enrolment flow, including sessions, CSRF tokens, TLS, security headers, identity-code verification, authenticator setup, recovery-code generation, and mobile-oriented styling. However, it does not fully meet the requirements because its displayed “QR code” is not a valid scannable QR code, recovery codes cannot be verified or consumed as single-use codes, and several retry/help/accessibility expectations are incomplete. Therefore, the artifact cannot be accepted as-is.

## FUNCTIONAL_CHECK

- **FAIL — Single-file Bun SPA with no framework, build tool, compiler, or external assets**
  - The app is contained in one `app.ts`, uses `Bun.serve`, inline HTML/CSS/JS, and no external assets or framework.
  - However, overall acceptance fails due to functional/security defects described below.

- **PASS — Bun TLS server uses the provided certificate paths**
  - The server reads `certs/cert.pem` and `certs/key.pem` and configures Bun TLS with them.
  - The app does not expose a plain HTTP listener.

- **PASS — Mobile-responsive, legible MFA enrolment UI**
  - The UI uses a constrained mobile layout, responsive viewport metadata, sufficiently large text, generous spacing, clear cards, and mobile-friendly numeric input modes.
  - The visual hierarchy and current-step indicator are generally clear.

- **PASS — Plain-language identity verification and authenticator enrolment flow**
  - The flow follows a predictable order: sign-in, identity check, authenticator setup, recovery codes, completion.
  - Inputs include examples such as `name@example.com` and `123456`.
  - Identity and authenticator errors are specific and suggest corrective actions.

- **FAIL — QR-code option is functional**
  - The `qr(uri)` function produces a deterministic random-looking 29×29 grid based on the URI. It does not perform QR encoding, include required QR structures, or create a scannable QR code.
  - A user cannot scan this output with an authenticator app, so the QR option is misleading and nonfunctional.
  - Manual secret and provisioning URI copying are present, but they do not make the invalid QR implementation acceptable.

- **PASS — Manual authenticator setup is available**
  - The setup secret and provisioning URI are displayed and can be copied with `navigator.clipboard`.
  - The authenticator verification code can be entered manually.

- **PASS — Browser mock values are logged without server-side secret logging**
  - Test identity OTPs, authenticator test codes, and recovery codes are logged through browser-side `console.log`.
  - The server itself does not log these secrets.
  - This meets the stated mock/testing delivery convention, subject to production configuration.

- **FAIL — Recovery codes can be verified and are single-use**
  - Recovery codes are generated and hashed, but there is no endpoint or UI flow to submit a recovery code.
  - `backupHashes`, `recoveryFails`, and `recoveryLockedUntil` exist, but recovery verification/consumption logic is never implemented.
  - Consequently, the claim “Each works once” is not enforced, and recovery verification does not work.

- **PASS — Server-side authorization and IDOR resistance for MFA management**
  - MFA endpoints derive the account identity from the server-side session.
  - No client-provided user ID is accepted for MFA operations.
  - `owner()` verifies the session stage and expected account ID before MFA endpoints proceed.

- **PASS — CSRF protection on state-changing requests**
  - State-changing API routes require an `x-csrf-token` matching the server-side session token.
  - Session cookies use `SameSite=Strict`, providing an additional browser-level CSRF defense.

- **PASS — Session security**
  - Session identifiers are generated with cryptographically secure randomness.
  - The session is rotated after successful password sign-in.
  - Cookies are configured with `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - Idle and absolute session expiry are implemented, and logout invalidates the session.

- **PASS — Secure response headers and CORS restriction**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `frame-ancestors 'none'` are provided.
  - CORS is restricted to explicit local HTTPS origins.
  - Errors are generic at the top-level request handler and do not expose stack traces.

- **PASS — OTP secret and recovery-code protection at rest**
  - Authenticator secrets are AES-GCM encrypted in server memory.
  - Recovery codes are hashed with SHA-256 and a process-secret pepper.
  - Cryptographically secure randomness is used outside test mode.

- **FAIL — Verification-code lifecycle requirements are complete**
  - Identity codes are time-bound, checked for reuse, and rate-limited.
  - Authenticator setup attempts are rate-limited and setup secrets expire.
  - However, recovery codes have no verification lifecycle at all: no validation, no single-use consumption, no expiry policy, and no recovery-attempt lockout despite fields being declared for it.

- **FAIL — Re-request, reveal/hide, and retry UX is complete**
  - Identity code re-request is supported.
  - The authenticator secret and provisioning URI are always visibly rendered once setup details are shown; there is no hide/reveal control for sensitive setup values.
  - Users cannot request replacement authenticator setup details while viewing current details unless the current setup has expired or failed.
  - This does not fully satisfy the requirement to let users “retry any step or reveal, hide and re-request codes without penalty.”

- **FAIL — Help/hints are easy to find at every step**
  - There are some inline explanatory sentences and success messages, but no consistent help or hint affordance at every screen.
  - In particular, sign-in and completion have no readily discoverable help mechanism, and setup guidance is not consistently structured as a reusable hint component.

- **FAIL — Login attempts are not rate-limited**
  - `/api/sign-in` accepts unlimited failed password attempts.
  - Although identity and authenticator-code attempts are locked after five failures, repeated password guessing remains possible.
  - This weakens the identification and authentication protections expected for the sign-in stage.

- **PASS — Input validation and output handling**
  - Server input is type-checked, trimmed, bounded in length, and format-validated where needed.
  - No SQL/database layer is used.
  - User-controlled values are not interpolated into HTML; secret and URI values are inserted with `textContent`.
  - No open redirect behavior is present.

## FAILING_ITEMS

- The QR display is not a genuine QR code and cannot be scanned by an authenticator application.
- Recovery codes are generated but cannot be submitted, verified, consumed, or locked out after repeated failures.
- The UI states that recovery codes work once, but there is no implementation enforcing that statement.
- `/api/sign-in` has no failed-attempt rate limit or lockout.
- The authenticator setup screen lacks controls to hide/reveal sensitive manual setup values and to request fresh setup details before an error or expiry.
- A consistent, easy-to-find help or hint mechanism is not present on every step.
- The code comments do not clearly map major implementation areas back to the numbered requirement sections as requested; the top-level comment is too broad to satisfy that deliverable reliably.

## NEW_TASKS

1. Replace `qr(uri)` with a real, standards-compliant QR encoder implemented in inline browser JavaScript, and render a QR code that authenticator apps can scan for the displayed provisioning URI.

2. Add a server-side recovery-code verification endpoint that:
   - Requires an authenticated, authorized session and CSRF validation.
   - Validates a submitted recovery-code format.
   - Hashes and compares the submitted value safely against stored recovery-code hashes.
   - Removes the matched hash after success so the code is single-use.
   - Applies failure counting and lockout using `recoveryFails` and `recoveryLockedUntil`.

3. Add a recovery-code verification UI route/screen so the generated codes can be tested and the recovery-code functionality is actually usable.

4. Add per-session and/or account-level failed sign-in attempt rate limiting and temporary lockout to `/api/sign-in`, while retaining generic non-enumerating sign-in error messages.

5. Add authenticator setup controls to hide/reveal the manual secret and provisioning URI, and add a clearly labeled “Show new setup details” action that safely replaces an active pending setup secret without requiring expiry or a failed verification.

6. Add a consistent, concise help/hint control or component on each enrolment step, using plain language and preserving the low-reading-load design.

7. Add clear comments adjacent to the relevant server and client sections that map authorization/CSRF, headers/TLS, secret storage, validation/XSS handling, and verification/lockout behavior to Security Requirements 1–5.

## DECISION

FAIL