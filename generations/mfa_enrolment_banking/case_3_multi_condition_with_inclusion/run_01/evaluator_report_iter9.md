## SUMMARY

The artifact is a single-file Bun HTTPS MFA enrolment application with a responsive, accessible mobile UI, simulated browser-console mock values, server-side sessions, CSRF checks, cryptographic generation/storage, secure headers, OTP/recovery-code verification, and rate limits. Most individual controls are implemented correctly. However, the completed MFA state is not recoverable after a reload, logout, or new sign-in: an already-enrolled user is always sent into provisioning, which the server correctly rejects as already active. This prevents access to the settings and backup-code regeneration functions except during the original in-memory client flow.

## FUNCTIONAL_CHECK

- **PASS — Single `app.ts` deliverable with Bun server, HTML, CSS, and browser JavaScript**
  - The entire application is contained in one TypeScript file.
  - It uses `Bun.serve`, inline HTML/CSS/JS, and no framework, bundler, compilation pipeline, or external assets.

- **PASS — HTTPS/TLS server configuration**
  - The Bun server is configured with `certs/cert.pem` and `certs/key.pem`.
  - HSTS is set on responses.

- **PASS — Mobile-responsive, dyslexia-conscious UX**
  - The layout has a mobile viewport meta tag, constrained responsive content width, large controls, generous spacing, readable font sizing, icons, short instructions, examples, and help disclosures.
  - It avoids animation, flashing content, dense prose, and all-caps instructional text.

- **PASS — Functional sign-in, identity-check, authenticator, OTP, backup-code, settings, and logout interactions during one uninterrupted client session**
  - Sign-in creates a session and supplies a browser-console demo identity code.
  - Identity verification gates authenticator provisioning.
  - Authenticator provisioning provides a QR code, revealable/copyable manual seed, and demo OTP.
  - OTP verification enables MFA and creates recovery codes.
  - Recovery codes can be copied, confirmed, tested once, and regenerated.
  - Logout invalidates the server session and clears the cookie.

- **FAIL — Enrolled-user state is recoverable and settings remain accessible after reload/new sign-in**
  - After successful OTP verification, `a.mfaEnabled` is set to `true`.
  - On any later browser refresh, logout/sign-in, expired client state, or new authenticated session, the client always routes to `identity`, then calls `/api/authenticator/provision`.
  - `/api/authenticator/provision` correctly returns `403 "Your authenticator is already active."` for enrolled users.
  - There is no endpoint to retrieve MFA status, no settings bootstrap route, and no UI transition to `settings` for an already-enrolled account.
  - Consequently, recovery-code regeneration and MFA settings are inaccessible after the original client state is lost.

- **FAIL — MFA enrolment completion is persisted as a distinct completed flow**
  - MFA is activated in `/api/authenticator/verify`, before the user confirms they saved the recovery codes.
  - `/api/backup/confirm` performs no persisted state change.
  - If the user reloads or leaves on the recovery-code screen, MFA is active but the user cannot resume the recovery-code confirmation or access settings after signing in again.

- **PASS — Manual alternatives to QR provisioning**
  - The authenticator secret can be revealed and copied manually.
  - OTP and recovery code entry fields support manual entry and `autocomplete="one-time-code"` where appropriate.
  - The QR code is generated locally without external requests.

- **PASS — Browser-console mock values**
  - Identity codes, authenticator OTP values, and backup recovery codes are emitted through browser-side `console.log`.
  - Sensitive values are not placed in the visible in-page “Logs” panel.
  - Server-side code does not log OTPs, seeds, backup codes, or sessions.

- **PASS — Server-side authorization / IDOR protection**
  - MFA endpoints derive the account from the authenticated `mfa_session` server-side session.
  - No client-supplied user/account identifier is accepted by protected MFA endpoints.
  - Session ownership is checked on each protected request.

- **PASS — CSRF protection for protected state-changing endpoints**
  - Protected POST endpoints require a same-origin allow-listed `Origin` and matching `X-CSRF-Token`.
  - Session cookies are `SameSite=Strict`.
  - The initial sign-in endpoint also requires an allow-listed Origin.

- **PASS — Secure session-cookie handling**
  - Cookies use `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, and bounded lifetime.
  - Sessions have idle and absolute expiration.
  - Sessions are newly generated on successful authentication and invalidated on logout.
  - Existing sessions for the account are removed upon a new successful sign-in.

- **PASS — Security headers and restricted CORS**
  - CSP with nonce-based inline script/style authorization is present.
  - HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, referrer policy, and permissions policy are configured.
  - CORS is restricted to explicitly allow-listed local HTTPS origins.

- **PASS — Cryptographic handling of secrets and codes**
  - Random values use `crypto.getRandomValues`.
  - The OTP seed is AES-GCM encrypted in server memory.
  - Recovery codes, credentials, OTP challenge codes, and consumed OTP markers are hashed.
  - TOTP validation uses HMAC-SHA-1 as required by the declared `otpauth` URI and accepts only current/adjacent time windows.
  - OTPs and recovery codes are single-use where applicable.

- **PASS — Input validation and output encoding**
  - Inputs have bounded parsing and format validation for email, credential, OTP, and recovery codes.
  - Client-side dynamic values inserted into HTML are escaped.
  - There are no SQL queries or redirect parameters, so SQL injection and open redirects are not introduced.

- **PASS — Verification expiry, replay prevention, rate limiting, and lockouts**
  - Identity codes expire and are single-use.
  - Provisioning expires.
  - TOTP values are rejected after use.
  - Identity, authenticator, recovery, and sign-in failures have lockouts/rate controls.
  - Error messages provide a problem and corrective action.

- **PASS — No external network dependencies**
  - QR generation is implemented locally.
  - All browser calls are same-origin API requests.
  - No external fonts, scripts, images, APIs, or assets are loaded.

## FAILING_ITEMS

- The application has no persisted/retrievable MFA status route or post-authentication routing for an account whose `mfaEnabled` is already true.
  - A refresh, logout, session expiry, or new sign-in after MFA activation leaves the user unable to reach security settings.
  - The user becomes stuck after the legitimate “already active” provisioning response.

- MFA activation occurs before recovery-code acknowledgement, while `/api/backup/confirm` does not persist a backup-confirmation/enrolment-completion state.
  - A user who loses client state on the recovery-code screen cannot resume that step.
  - This breaks the intended secure recovery-code storage stage of the enrolment flow.

## NEW_TASKS

1. Add a protected MFA-status endpoint, for example `GET /api/mfa/status`, that returns only the authenticated account’s non-sensitive MFA state, such as `identityVerified`, `mfaEnabled`, and a persisted `backupCodesConfirmed` flag.

2. Update the client sign-in/identity routing so that an account with active MFA is sent to the security settings screen rather than attempting authenticator provisioning again.

3. Add a persisted `backupCodesConfirmed` field to `Account`; set it only in `/api/backup/confirm`.

4. Decide and enforce the intended enrolment state transition:
   - either defer `mfaEnabled = true` until `/api/backup/confirm`, or
   - retain MFA activation at OTP verification but provide a protected resumable recovery-code screen until `backupCodesConfirmed` is true.

5. Ensure a user returning after reload/new sign-in can regenerate recovery codes and complete any outstanding recovery-code confirmation without receiving the blocking “authenticator is already active” provisioning error.

## DECISION

FAIL