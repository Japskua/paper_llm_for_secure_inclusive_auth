## SUMMARY

The artifact is a strong single-file Bun MFA enrolment SPA with responsive, dyslexia-conscious UI, working simulated OTP/TOTP and recovery-code flows, HTTPS/TLS, CSP and other security headers, CSRF checks on authenticated state changes, encrypted OTP-secret storage, hashed recovery codes, and server-side authorization. However, it does not fully meet secure session-management requirements because signing in creates a new session without invalidating existing sessions for the same account. As a result, logging out of the newest session does not invalidate older active sessions.

## FUNCTIONAL_CHECK

- **Single `app.ts` file containing Bun server, HTML, CSS, and vanilla browser JavaScript — PASS**
  - The server, TLS configuration, HTML template, inline CSS, and client-side JavaScript are all contained in the supplied `app.ts`.
  - No framework, bundler, compiler, or external assets are used.

- **Bun HTTPS server uses supplied certificates — PASS**
  - `Bun.serve` is configured with `tls: { cert: readFileSync("certs/cert.pem"), key: readFileSync("certs/key.pem") }`.
  - The application is served over TLS and includes HSTS.

- **Responsive mobile SPA and accessible/dyslexia-conscious UI — PASS**
  - The page has a mobile viewport meta tag, constrained mobile-friendly layout, readable font sizing, generous line/letter spacing, plain language, prominent primary actions, examples for expected codes, persistent help, and no animated/time-pressure UI.
  - Inputs use suitable autofill and input-mode attributes, including `autocomplete="one-time-code"` and `inputmode="numeric"`.

- **Functional enrolment flow: sign-in, identity verification, authenticator setup, backup codes, completion — PASS**
  - The flow progresses through sign-in, six-digit identity code confirmation, authenticator provisioning, authenticator-code confirmation, recovery-code saving, and MFA activation.
  - State restoration endpoints support returning to pending identity/setup/recovery-code stages.

- **Authenticator setup supports QR and manual entry/copying — PASS**
  - A QR code is generated locally without external assets.
  - The shared secret and full provisioning URI can be revealed and copied.
  - The setup key can be manually entered into an authenticator app.

- **Simulated values are available for evaluation and logged in the browser — PASS**
  - Demo identity OTP, deterministic authenticator test code, and recovery codes are returned to the authenticated UI and written with browser-side `console.log`.
  - No server-side logging of OTPs, seeds, recovery codes, or session tokens is present.

- **OTP and recovery-code verification works, is single-use/time-bound, and is rate-limited — PASS**
  - Identity OTPs expire after 20 minutes and are marked used after successful verification.
  - TOTP counters are recorded to prevent reuse.
  - Recovery codes are hashed and marked used after successful use.
  - Failed verification attempts are limited to five before a five-minute lockout.

- **Server-side authorization and IDOR resistance — PASS**
  - Authenticated MFA endpoints derive the user from the secure session rather than accepting a client-provided user identifier.
  - MFA records are accessed only through `session.userId`.
  - Guessed or manipulated user IDs cannot be supplied to access another user’s MFA data.

- **CSRF protection for authenticated state-changing MFA operations — PASS**
  - State-changing authenticated requests require `X-CSRF-Token` to match the server-side session token.
  - Session cookies use `SameSite=Strict`.
  - Origin checking rejects untrusted protocols/hosts.

- **Secure HTTP response headers and restrictive CSP — PASS**
  - The app sets CSP with per-response nonces, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, permissions restrictions, and no-store caching.
  - CORS response headers are not permissive.

- **Sensitive MFA material is protected at rest — PASS**
  - OTP secrets are AES-GCM encrypted in the server-side MFA record.
  - Recovery codes are stored as PBKDF2-SHA-256 hashes with per-code random salts.
  - Production-mode secrets and recovery codes use `crypto.getRandomValues`.

- **Input validation and output encoding — PASS**
  - Server-side validation is applied to emails, OTPs, and recovery codes.
  - Dynamic client-rendered values are escaped before insertion into HTML.
  - No database layer or SQL queries exist, so parameterized-query requirements are not applicable.

- **Session fixation prevention and timeout handling — PARTIAL / FAIL**
  - A new random session ID is generated after successful sign-in, which helps prevent session fixation.
  - Idle and absolute timeouts are implemented.
  - However, existing sessions for the same account are not invalidated when a new sign-in occurs, and logout invalidates only the current session. Older sessions remain usable.

- **Session invalidation on logout — FAIL**
  - `/api/logout` only runs `sessions.delete(id)` for the currently presented session cookie.
  - If the account has previously signed in from another browser/tab/device, those prior session IDs remain valid until timeout.
  - This does not fully satisfy the requirement to invalidate sessions securely on logout.

## FAILING_ITEMS

- **Existing sessions are not invalidated when the user signs in again.**
  - Successful `/api/signin` creates and stores a new session but does not remove older sessions whose `userId` matches the authenticated account.
  - An old session can remain active after a fresh sign-in, contrary to robust session rotation expectations.

- **Logout invalidates only the current session, not all active account sessions.**
  - `/api/logout` deletes only `sessions.delete(id)`.
  - Any previous valid session ID for the same user remains authorized and can continue viewing or modifying MFA state until its timeout.

## NEW_TASKS

1. Add a helper that removes all sessions belonging to a specified `userId`, optionally preserving one newly created session ID.

2. In `/api/signin`, invalidate all existing sessions for `USER.id` before storing the newly generated authenticated session.

3. In `/api/logout`, invalidate all sessions belonging to `session.userId`, then clear the current session cookie.

4. Verify that an old session cookie cannot call `/api/state`, `/api/mfa/verify`, or any MFA-changing endpoint after the user signs in again or signs out.

## DECISION

FAIL