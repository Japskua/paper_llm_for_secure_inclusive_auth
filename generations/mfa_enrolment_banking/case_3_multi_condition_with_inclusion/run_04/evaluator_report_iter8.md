## SUMMARY

The artifact is a single `app.ts` Bun HTTPS SPA and implements much of the required MFA flow: sign-in, identity OTP, authenticator setup with QR/provisioning URI, recovery-code generation, secure cookies, CSRF tokens, CSP/HSTS, encrypted OTP-secret storage, hashed recovery codes, and server-side session ownership checks. However, it does not fully satisfy the requirements because lockouts can be bypassed, test fixtures are incomplete/non-deterministic, recovery-code UX lacks copying and re-generation, manual setup is insufficiently supported, and several retry/error paths are broken or incomplete.

## FUNCTIONAL_CHECK

- **FAIL — Single-file Bun application with no framework/build tooling**
  - The entire server and browser app are in `app.ts`, and Bun serves the inline HTML/CSS/JS directly.
  - However, the application requires certificate files at startup and will terminate if `certs/cert.pem` or `certs/key.pem` are unavailable. This is acceptable only if the required files are actually supplied as stated.

- **PASS — HTTPS/TLS and security headers**
  - Bun is configured with TLS certificates.
  - Responses include CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, referrer policy, and permissions policy.
  - The session cookie uses `HttpOnly`, `Secure`, and `SameSite=Strict`.

- **PASS — Server-side ownership checks / IDOR prevention**
  - MFA endpoints use `owner(r)`, which requires a session in the MFA stage and verifies the session’s `userId` equals the fixed account ID.
  - No client-provided user identifier is accepted by MFA endpoints, preventing guessed-ID manipulation.

- **PASS — CSRF protection on state-changing endpoints**
  - State-changing endpoints require an `x-csrf-token` matching the server-side session token.
  - Cookies are also `SameSite=Strict`.

- **FAIL — Rate limiting and lockout enforcement**
  - Identity verification increments `identityFails` and sets `identityLockedUntil`, but `/api/identity/verify` never checks `identityLockedUntil`. A user can continue submitting codes, including a correct one, after lockout.
  - Authenticator verification sets `otpLockedUntil`, but `/api/authenticator/verify` never checks it.
  - `/api/authenticator/start` resets OTP failures and permits creating a new pending secret even after lockout, bypassing the intended pause entirely.

- **PASS — Session handling**
  - The session ID is regenerated after successful password sign-in, mitigating session fixation.
  - Idle and absolute timeouts are implemented.
  - Logout deletes the server session and clears the cookie.

- **PASS — Sensitive data handling at rest**
  - Authenticator secrets are encrypted with AES-GCM.
  - Recovery codes are hashed before storage.
  - Cryptographic random generation is used in production paths.

- **FAIL — Deterministic browser mock behavior**
  - The identity OTP fixture is deterministic (`123456`) in test mode.
  - The authenticator fixture is generated from time-based TOTP and therefore changes every 30 seconds; it is not deterministic.
  - Recovery codes are shown in the UI but are not logged with `console.log` in the browser, despite the requirement that backup recovery codes be returned to the UI and shown in the browser console for testing.

- **FAIL — Avoid exposing secrets/codes through visible logs**
  - The page contains a visible “Logs” panel. Test OTPs are written both to `console.log` and into the page DOM through `logs.textContent`.
  - This unnecessarily exposes sensitive test values in the rendered interface. The requirement calls for browser-console mocks, not an on-screen debug-log panel.

- **FAIL — Manual authenticator setup support**
  - The setup page shows a QR code and a full provisioning URI.
  - It does not present the base32 secret as a clearly labeled manual-entry value with its own copy action. A user who cannot scan a QR code may need to parse a long URI instead of copying or entering a plainly labeled secret.

- **FAIL — Recovery-code usability**
  - Recovery codes are displayed but have no copy-to-clipboard action.
  - This conflicts with the requirement to reduce manual transcription of long codes and offer copy support.
  - The UI does not expose recovery-code regeneration after codes have been created, despite the server supporting `/api/backup/regenerate`.

- **FAIL — Retry and recovery UX**
  - If authenticator setup expires, `/api/authenticator/details` returns an error telling the user to “Show new setup details,” but the UI does not provide a button to start a new setup.
  - If authenticator verification fails repeatedly, the error message says to wait and then show new setup details, but no UI path is provided from the setup-details screen to do that.
  - The recovery-code generation handler assumes success and directly calls `d.codes.join(...)`; if the API returns an error, it can cause a browser-side runtime error instead of showing a clear message.

- **FAIL — Plain confirmation and predictable UX after actions**
  - Several actions immediately replace the current screen without an explicit plain-language confirmation of what happened and what comes next.
  - “Send a new code” has no visible success confirmation; it only emits a test value to logs.
  - The visible debug-log section adds clutter and is not appropriate for the intended dyslexia-friendly production-style flow.

- **PASS — Mobile-oriented visual layout and accessibility basics**
  - The page uses a narrow responsive layout, readable base font size, spacing, short instructions, semantic forms and labels, `autocomplete` fields, and `inputmode="numeric"` for OTP inputs.
  - It avoids animation, flashing, and dense blocks of text.

- **PASS — Internal navigation/API flow**
  - The SPA routes between sign-in, identity verification, authenticator setup, backup codes, completion, and logout without external links or external network requests.

- **PASS — Generic error handling and restricted CORS**
  - The top-level handler returns generic errors rather than stack traces.
  - Origins are allow-listed and CORS headers are only issued for approved local HTTPS origins.

## FAILING_ITEMS

- Identity-code lockout is recorded but not enforced by `/api/identity/verify`.
- Authenticator-code lockout is recorded but not enforced by `/api/authenticator/verify`.
- Authenticator lockout can be bypassed by calling `/api/authenticator/start`, which resets failure state and creates a new setup.
- Test authenticator OTP values are time-dependent rather than deterministic.
- Recovery codes are not emitted to the browser console in test mode.
- The on-page “Logs” panel exposes test OTP values in the rendered UI and adds unnecessary visual clutter.
- The authenticator setup page does not clearly expose the base32 secret for manual setup/copying; it only exposes a long provisioning URI.
- Recovery codes cannot be copied to the clipboard.
- The UI does not offer recovery-code regeneration after generation.
- Authenticator-expiry and lockout error paths leave the user without a clear UI action to generate fresh setup details.
- Backup-code UI does not handle API failures before accessing `d.codes`, which can produce a client-side error.
- Several user actions lack visible, plain-language success confirmation.

## NEW_TASKS

1. Enforce identity and authenticator lockouts server-side:
   - Reject `/api/identity/verify` while `identityLockedUntil` is active.
   - Reject `/api/authenticator/verify` while `otpLockedUntil` is active.
   - Reject or safely handle `/api/authenticator/start` while the authenticator lockout is active.
   - Reset failure/lock fields only after the lock has expired and a new setup/code is legitimately issued.

2. Make test fixtures compliant:
   - Use a deterministic authenticator verification fixture in test mode and make server verification accept that deterministic fixture only in test mode.
   - Log test recovery codes with `console.log` in the browser when they are generated.
   - Keep production behavior cryptographically generated and do not expose test fixtures in production.

3. Remove the rendered debug-log panel:
   - Eliminate the visible `<section class="logs">` and browser DOM logging.
   - Keep required test mock output in `console.log` only.

4. Improve manual authenticator setup:
   - Display the base32 secret in a labeled manual-setup field.
   - Add a dedicated “Copy secret” action.
   - Retain QR and provisioning-URI options, with clear concise instructions.

5. Improve recovery-code UX:
   - Add a “Copy recovery codes” action.
   - Add a clear confirmation after copying.
   - Add a controlled “Create new recovery codes” action after initial generation, with an appropriate confirmation that old codes will stop working.

6. Repair retry and error paths:
   - Add a “Show new setup details” / “Start again” action when authenticator setup expires or is locked.
   - Handle failed backup-code generation before reading `d.codes`.
   - Render all API errors as clear user-facing messages rather than allowing client-side exceptions.

7. Add concise visible success feedback:
   - Confirm when a new identity code is sent.
   - Confirm when setup details are shown/copied.
   - Confirm when recovery codes are created/copied/regenerated.
   - Preserve one clear primary action per screen.

## DECISION

FAIL