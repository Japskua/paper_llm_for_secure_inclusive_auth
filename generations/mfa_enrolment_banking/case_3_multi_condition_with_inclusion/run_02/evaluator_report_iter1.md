## SUMMARY

The artifact is a single-file Bun HTTPS SPA with a generally clear, mobile-friendly MFA enrolment flow. It includes server-side sessions, CSRF checks, TLS, CSP/security headers, rate limiting, and encrypted in-memory authenticator secrets. However, it does not fully meet the MFA, QR, state-recovery, deterministic-mock, and secret-exposure requirements. In particular, the displayed “QR code” is not a valid QR code, authenticator verification is not TOTP-based, refresh/re-entry states are broken, and OTP secrets/codes/recovery codes are exposed in a visible log panel and browser console.

## FUNCTIONAL_CHECK

- **Single-file `app.ts`, Bun server, inline HTML/CSS/vanilla JS, no frameworks/build tools/external assets — PASS**
  - The server, UI template, CSS, and client-side JavaScript are all contained in `app.ts`.
  - It uses `Bun.serve` directly and does not rely on bundlers, frameworks, or remote assets.

- **TLS/HTTPS using the supplied certificate paths — PASS**
  - The server uses `certs/cert.pem` and `certs/key.pem` through Bun TLS configuration.
  - HSTS is sent in response headers.

- **Responsive, mobile-readable, dyslexia-considerate UI — PASS**
  - The UI has a constrained mobile layout, readable font size, spacing, short instructions, non-italic instructional text, input examples, icons, and prominent primary actions.
  - It avoids animations, timers in the UI, flashing elements, and dense content.

- **Plain-language enrolment flow with sign-in, identity confirmation, authenticator setup, recovery codes, and completion — PASS**
  - The intended five-step sequence is implemented.
  - Inputs include examples and suitable browser autocomplete values such as `username`, `current-password`, and `one-time-code`.

- **Retry/help/re-request support — PARTIAL / FAIL**
  - Identity-code resend is implemented.
  - However, authenticator setup cannot safely be revisited: revisiting setup generates a new secret and OTP, replacing the previous setup.
  - Recovery codes cannot be re-requested or regenerated from the UI.
  - Recovery codes are not reveal/hide controlled; they are always exposed on the screen and log panel.

- **QR-code option for authenticator provisioning — FAIL**
  - `drawQR()` produces a pseudo-random visual grid, not a standards-compliant QR code encoding the `otpauth://` URI.
  - An authenticator application cannot scan this canvas to provision the account.
  - The canvas is labeled as a “Setup QR code,” which is misleading because it is not a real QR code.

- **Manual alternative to QR/provisioning — PARTIAL / FAIL**
  - A setup secret is available through the “Copy setup key” button and is written to the browser log.
  - The secret is not clearly displayed in the main UI for a user who cannot use clipboard access.
  - The full provisioning URI is not shown or available for manual copying/import.

- **Authenticator verification works as a TOTP authenticator — FAIL**
  - `/api/authenticator/start` creates a random six-digit value and `/api/authenticator/verify` validates that one stored value.
  - This is a one-time setup code, not a time-based OTP calculated from the shared secret.
  - The generated authenticator secret is encrypted but never used to calculate or verify an RFC 6238 TOTP.
  - Therefore scanning/entering the secret into a real authenticator app would not produce a code accepted by the server.

- **Mock OTP/provisioning values are deterministic and available through browser console logging — FAIL**
  - The requirements explicitly call for deterministic mock values.
  - `sixDigits()`, secrets, recovery codes, salts, session IDs, and CSRF tokens are random on each run.
  - The browser console logging requirement is implemented, but the mock values are not deterministic.

- **Server-side authorization and IDOR protection — PASS**
  - API routes derive the account from the HttpOnly session instead of accepting a browser-provided user ID.
  - The authenticated session’s `userId` is checked against the server-side account.
  - MFA records are indexed only by the authenticated server-side user ID.

- **CSRF protection on state-changing operations — PASS**
  - State-changing API calls require the session-bound `X-CSRF-Token`.
  - The session cookie uses `SameSite=Strict`.
  - Sign-in is exempt because it creates the session rather than changing an authenticated account state.

- **Secure session management — PASS**
  - Sessions are server-side, regenerated on sign-in, bound to an HttpOnly/Secure/SameSite cookie, expire after idle and absolute limits, and are invalidated on logout.
  - Session tokens are not stored in localStorage, sessionStorage, or readable cookies.

- **Security headers and restricted external access — PASS**
  - CSP with nonces, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, no-store caching, referrer policy, and permissions policy are present.
  - No broad `Access-Control-Allow-Origin: *` configuration is used.

- **No verbose server error details — PASS**
  - The top-level request handler returns a generic error response and does not expose stack traces.

- **Secrets and codes are protected at rest — PARTIAL / FAIL**
  - The authenticator secret is AES-GCM encrypted in server memory.
  - Recovery codes are salted and hashed, but the hash is plain SHA-256 rather than a deliberately slow password/recovery-code hashing scheme such as PBKDF2, scrypt, or Argon2.
  - For short human-entered recovery codes, a fast SHA-256 hash is not sufficient protection against offline guessing if storage is exposed.

- **Secrets, OTPs, and recovery codes are not exposed in logs — FAIL**
  - The client intentionally logs the identity OTP, authenticator secret, authenticator OTP, and recovery codes with `console.log`.
  - It additionally renders these values in the visible “Logs for this demo” panel.
  - This directly conflicts with the security requirement prohibiting OTP seeds, OTPs, and backup codes in logs.
  - The requirements themselves contain a conflict because the deliverables also demand browser `console.log` output of mock OTPs and backup codes; the visible in-page log panel is not required by that deliverable and should not expose secrets.

- **Input validation and output encoding — PASS**
  - Email and OTP formats are validated server-side.
  - OTPs are restricted to six digits.
  - Client-rendered recovery codes and error messages are escaped before insertion into HTML.
  - There is no database query layer, so SQL injection does not apply to this implementation.

- **Rate limiting, lockout, expiry, and single-use verification codes — PARTIAL / FAIL**
  - Identity and setup codes expire, are single-use, and failed attempts are rate-limited with a temporary lockout.
  - However, the authenticator “OTP” is not an authenticator-generated TOTP and cannot be validated against the stored secret.
  - There is no post-enrolment MFA verification endpoint that accepts an authenticator TOTP or recovery code for a protected action.

- **State restoration and internal flow continuity — FAIL**
  - `/api/state` may return `"backup"`, but the client `begin()` function has no `"backup"` branch and falls back to `signIn()`.
  - Refreshing after authenticator verification but before acknowledging recovery codes therefore breaks the flow.
  - When `/api/state` returns `"setup"`, `begin()` calls `startSetup()`, which requests a new setup secret and overwrites the existing enrolment record instead of displaying the existing state.

## FAILING_ITEMS

- The canvas “QR code” is not an actual scannable QR code containing the provisioning URI.
- The authenticator code is a server-generated random setup code, not a TOTP derived from the authenticator secret.
- Mock values are random, despite the requirement for deterministic mock values.
- Reloading during setup regenerates and overwrites the authenticator secret and pending OTP.
- Reloading during the recovery-code step routes the user back to sign-in because `"backup"` state is not handled by the client.
- Recovery codes cannot be safely re-requested/regenerated, and the flow does not provide complete retry/recovery behavior at every stage.
- The manual provisioning option is insufficient because the setup secret and provisioning URI are not clearly available in the primary UI when clipboard support is unavailable.
- The visible in-page logs panel exposes the authenticator seed, OTPs, and recovery codes.
- Browser `console.log` also exposes secrets and codes, conflicting with the security requirement that such values must never appear in logs.
- Recovery codes use fast salted SHA-256 rather than a slow, strong password/recovery-code hashing function.
- No post-enrolment endpoint exists to verify a TOTP or consume a recovery code for a protected MFA action.
- The specification contains a direct conflict: it requires browser-console logging of mock secrets/codes while also forbidding secrets/codes in logs. This must be resolved explicitly; the current implementation does not provide a safe separation between an evaluator-only mock mode and a secure production mode.

## NEW_TASKS

1. Replace `drawQR()` with a real, standards-compliant QR encoder that encodes the returned `otpauth://totp/...` provisioning URI without using external assets.

2. Implement real server-side TOTP generation and verification using the provisioned shared secret, including an accepted time window and clear retry messages; retain a controlled test-mode mock value only if explicitly required.

3. Make test/mock OTP and recovery-code behavior deterministic as required, while clearly separating deterministic evaluator fixtures from cryptographically secure production generation.

4. Preserve incomplete authenticator setup server-side and add an authenticated endpoint to retrieve the existing pending provisioning state without generating or overwriting a new secret.

5. Add handling for the `"backup"` state in `begin()` so refresh returns the user to the recovery-code completion step rather than sign-in.

6. Add a secure recovery-code reissue/regeneration flow, protected by authorization and CSRF checks, that invalidates the old recovery-code set and plainly confirms the replacement.

7. Display a manually usable setup secret and optionally the full provisioning URI in the setup UI, with clear reveal/hide and copy controls, rather than relying on a debug log panel.

8. Remove the visible in-page secret log panel. Resolve the conflict between required evaluator console mocks and the “no secrets in logs” security rule by implementing an explicitly isolated evaluator/demo mode or by obtaining a clarified requirement; production behavior must never log seeds, OTPs, or recovery codes.

9. Replace salted SHA-256 recovery-code hashing with a slow, strong KDF such as PBKDF2, scrypt, or Argon2, using unique salts and appropriate work factors.

10. Add a protected post-enrolment MFA verification endpoint that can validate a current TOTP or consume a single-use recovery code, with rate limits and lockout behavior.

## DECISION

FAIL