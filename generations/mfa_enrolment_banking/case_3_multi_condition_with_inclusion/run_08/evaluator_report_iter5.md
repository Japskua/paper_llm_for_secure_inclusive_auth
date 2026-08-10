## SUMMARY

The artifact is a single-file Bun HTTPS SPA with a strong mobile-oriented MFA enrolment UI, simulated browser-side test logging, CSRF tokens for authenticated state changes, secure headers, TOTP verification, recovery-code hashing, and TLS configuration. However, it does not fully meet the authentication-security and recovery-flow requirements: account-credential attempts are not rate-limited or locked out, recovery codes cannot be used as an MFA fallback unless the session has already completed MFA, and malformed authenticated API requests become generic HTTP 500 errors instead of clear validation responses.

## FUNCTIONAL_CHECK

- **Single-file Bun application with no frameworks, bundlers, external assets, or compilation workflow: PASS**
  - The server, HTML, CSS, and browser JavaScript are contained in `app.ts`.
  - It uses `Bun.serve` directly and references only the required local TLS certificate files.

- **HTTPS/TLS use with supplied mkcert certificate paths: PASS**
  - Bun is configured with `certs/cert.pem` and `certs/key.pem`.
  - HSTS is included in responses.

- **Mobile-responsive and dyslexia-conscious UI: PASS**
  - The UI has a narrow mobile shell, adequate input/button sizes, generous spacing, plain-language copy, examples for inputs, visible progress labels, no animated content, and accessible focus styling.
  - It provides QR, copy buttons, autofill hints, retry/resend controls, and browser console demo values.

- **Identity-code simulation and verification: PASS**
  - Identity codes are CSPRNG-generated, time-bound, single-use, shown in the browser console/demo log, and checked server-side.
  - Invalid attempts are counted and lock after five failures.

- **Authenticator provisioning and TOTP verification: PASS**
  - A provisioning URI, QR code, manual secret, and copy controls are provided.
  - The secret is encrypted in server memory using AES-GCM.
  - TOTP verification supports a small clock window, rejects reused accepted time steps, and applies attempt lockout.

- **Recovery-code generation, display, copying, and one-time verification: PARTIAL / FAIL**
  - Recovery codes are generated with CSPRNG, displayed, copyable, hashed server-side, and deleted after successful use.
  - However, the recovery verification endpoint requires `session.mfaVerified`. A user who has lost authenticator access would normally have completed first-factor/identity authentication but would not be MFA-verified yet. Therefore recovery codes cannot serve their intended MFA fallback purpose.

- **Server-side authorization and IDOR prevention: PASS**
  - Protected routes require a server session, and the authenticated session is tied to the sole mock account.
  - Client-provided `userId` values are rejected if they differ from the session owner.
  - No API route trusts a client-provided account identifier to select MFA state.

- **CSRF protection for authenticated state-changing MFA routes: PASS**
  - Protected POST routes require an `X-CSRF-Token` matching the server-side session token.
  - Session cookies use `SameSite=Strict`.

- **Secure headers, secure cookies, restrictive CORS, and generic server errors: PASS**
  - CSP, HSTS, `X-Content-Type-Options`, `X-Frame-Options`, referrer policy, permissions policy, cache prevention, and origin-restricted CORS are present.
  - The session cookie is `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - The top-level error handler avoids exposing stack traces.

- **Input validation and output encoding: PARTIAL / FAIL**
  - Email, credentials, OTPs, and recovery-code formats are validated, and browser-rendered dynamic text is escaped.
  - But malformed JSON or invalid body/content-type on authenticated endpoints propagates to the outer catch and produces HTTP 500 with “Something went wrong,” rather than a clear client validation error explaining the problem and fix.

- **Rate limiting and lockout of repeated authentication failures: FAIL**
  - Identity-code, TOTP, and recovery-code attempts are rate-limited and locked.
  - `/api/auth/owner`, which verifies the account credential and creates a session, has no attempt counter, lockout, or rate limiting. An attacker can make unlimited credential guesses, only slowed by a fixed 180 ms delay.

- **Secure session management: PASS**
  - A new session is issued after owner credential verification, replacing any prior session cookie.
  - Idle and absolute timeouts are enforced.
  - Logout invalidates the server-side session and clears the cookie.

## FAILING_ITEMS

- **Credential verification has no rate limiting or lockout.**
  - `POST /api/auth/owner` accepts unlimited failed credential attempts.
  - The fixed delay is not a sufficient replacement for a bounded failure counter and lockout requirement.

- **Recovery codes cannot be used for actual MFA recovery.**
  - `POST /api/mfa/recovery/verify` rejects requests unless `session.mfaVerified` is already true.
  - This defeats recovery use when the authenticator is unavailable, because the user cannot become MFA-verified without the authenticator.

- **Malformed authenticated API requests produce HTTP 500 instead of a clear validation error.**
  - `requestBody(req)` is called after authentication without a local error handler.
  - Invalid JSON, an invalid content type, oversized body, or malformed content length reaches the outer `catch`, returning a generic 500 response.
  - This conflicts with the requirement for clear, specific error messages and correct input-validation handling.

## NEW_TASKS

1. Add server-side failed-attempt tracking and a lockout/rate-limit policy for `/api/auth/owner`; return the same non-enumerating credential error until the configured lockout threshold is reached.

2. Change the recovery-code authorization model so a user who has passed first-factor/identity verification can verify a recovery code before `session.mfaVerified` is true; on successful recovery verification, mark the session MFA-verified and consume the code.

3. Wrap `requestBody(req)` handling for authenticated routes in explicit validation error handling; return HTTP 400 or 413 with plain-language, non-sensitive messages for invalid JSON, wrong content type, and oversized request bodies rather than falling through to HTTP 500.

## DECISION

FAIL