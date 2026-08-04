## SUMMARY

The artifact is a valid single-file Bun + vanilla HTML/CSS/JavaScript SPA and implements most of the requested recovery flow with TLS, CSP, session-bound CSRF, token hashing, MFA, password policy, throttling, and safe DOM handling. However, it does not meet the reset-token **single-use** requirement: a successfully verified recovery token can be submitted repeatedly until password creation, generating new MFA challenges each time. Therefore the artifact must not be accepted as fully compliant.

## FUNCTIONAL_CHECK

- **PASS — Single-file, zero-compilation delivery**
  - All server logic, HTML, CSS, and browser JavaScript are contained in `app.ts`.
  - It uses Bun directly, without frameworks, bundlers, compilation steps, external assets, or network calls.

- **PASS — TLS certificate use and HTTPS session protection**
  - The Bun server uses `certs/cert.pem` and `certs/key.pem` when present.
  - The recovery session cookie is `Secure`, `HttpOnly`, `SameSite=Strict`, scoped to `/`, and uses the valid `__Host-` prefix constraints.
  - When certificates are absent, the server returns a safe `503` and exposes no recovery functionality.

- **PASS — Security headers and browser hardening**
  - HSTS, CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, Referrer Policy, Permissions Policy, and no-cache headers are configured.
  - CSP uses a per-response nonce for the trusted inline application script and blocks untrusted scripts and external sources.

- **PASS — CSRF prevention and sensitive-route access control**
  - Every changing API route requires a valid server session.
  - Every API request validates a session-specific CSRF token.
  - Requests must have an HTTPS same-origin `Origin` matching the request host.
  - No client-controlled account, patient, folder, or resource identifier is accepted by sensitive state-changing endpoints.

- **PASS — Input/output XSS protections**
  - User-provided input is not inserted through `innerHTML`.
  - The UI uses `textContent`, text nodes, and controlled attribute values.
  - URL-fragment token parsing validates the token format before using it and never renders arbitrary fragments.
  - There are no external scripts or untrusted script execution paths.

- **PASS — Recovery flow and manual/link token submission**
  - A recovery token is generated with `crypto.getRandomValues`, hashed server-side, and expires after 10 minutes.
  - The simulated recovery token is returned to the UI, displayed for testing, logged in the browser console, and can be submitted manually.
  - The generated recovery link populates the token form from the URL fragment and allows verification.

- **FAIL — Password reset token is single-use**
  - `/api/verify-reset` only checks `reset.used`, but does not set `reset.used = true` after successful verification.
  - A valid reset token can therefore be posted repeatedly before password submission.
  - Each repeated verification succeeds and replaces the MFA record with a fresh MFA challenge.
  - This violates the requirement that password reset tokens be single-use.

- **PASS — MFA and brute-force controls**
  - MFA is only issued after successful reset-token verification.
  - MFA codes expire after five minutes.
  - Incorrect MFA attempts are counted and lock the MFA step for five minutes after five failures.
  - The deterministic MFA value is appropriately used only as a testing mock and is logged in the browser.

- **PASS — Password security**
  - Password policy is checked both client-side and server-side.
  - The server requires 12–128 characters, upper/lowercase, number, symbol, no spaces, and rejects several predictable terms.
  - Passwords are hashed with Bun bcrypt before being retained.
  - Plaintext passwords are not stored, returned, or logged.

- **PASS — Privacy acceptance workflow**
  - Privacy acceptance is only allowed after password recovery has completed.
  - The acceptance checkbox is required in the UI and `accepted === true` is enforced server-side.
  - The completion screen is reachable through the intended workflow.

- **PASS — Privacy, phishing, and data exposure safeguards**
  - The UI contains clear warnings against sharing passwords or recovery/security codes.
  - Account input is not persisted, returned, or included in logs.
  - Generic recovery messaging reduces account-enumeration disclosure.
  - Errors do not expose stack traces or debug details.

## FAILING_ITEMS

- **Recovery tokens are reusable after successful verification.**
  - In `/api/verify-reset`, successful verification sets only `reset.verified = true`.
  - It does not consume/invalidate the reset token at verification time.
  - Reposting the same valid token repeatedly returns `ok: true` and repeatedly creates a new MFA record.
  - This fails the explicit requirement for random, **single-use**, short-lived password-reset tokens.

## NEW_TASKS

1. **Separate reset-token consumption from password-update completion.**
   - Add an explicit state field such as `tokenConsumed` or `resetVerifiedAt` to `ResetRecord`.
   - On a successful `/api/verify-reset` request, atomically mark the recovery token as consumed before returning success.

2. **Reject repeated reset-token verification requests.**
   - Update `/api/verify-reset` so a token already consumed after a successful verification always returns the existing invalid/expired/used response.
   - Do not create or replace an MFA challenge on a repeated token submission.

3. **Preserve the authorized recovery progression after token consumption.**
   - Update `/api/password` to rely on the verified recovery state plus successful MFA, rather than treating a consumed token as an automatic failure.
   - Retain a separate completion guard, such as `passwordUpdated`, to prevent duplicate password-update operations.

## DECISION

FAIL