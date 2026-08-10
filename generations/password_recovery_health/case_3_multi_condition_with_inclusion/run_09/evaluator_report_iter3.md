## SUMMARY

The artifact is a single-file Bun HTTPS SPA with a generally strong implementation of session-bound CSRF protection, secure headers, bcrypt password hashing, rate limiting, escaped DOM rendering, and a calm, accessible recovery UI. The recovery mock values are logged in the browser as required. However, it does not fully meet the stated security and continuity requirements: reset tokens are reusable before password completion, and a user who pauses or refreshes after successfully changing the password is incorrectly returned to the beginning instead of the sign-in step.

## FUNCTIONAL_CHECK

- **Single `app.ts` file containing Bun server, HTML, CSS, and vanilla browser JavaScript — PASS**
  - The supplied artifact is one TypeScript file and embeds the SPA template, CSS, and client JavaScript.

- **No frameworks, bundlers, external assets, or external network calls — PASS**
  - The code uses Bun and Node’s built-in crypto module only. The UI has no third-party assets, package dependencies, or outgoing fetches beyond same-origin API routes.

- **HTTPS server using `certs/cert.pem` and `certs/key.pem` — PASS**
  - `Bun.serve` is configured with TLS material read from the required certificate paths. The service does not start if certificates are unavailable.

- **Secure HTTP response configuration — PASS**
  - HSTS, CSP with a per-page nonce, `X-Content-Type-Options`, frame restrictions, referrer policy, permissions policy, and no-store caching headers are configured.
  - The application is served through TLS only.

- **CSRF protection on sensitive actions — PASS**
  - A cryptographically random CSRF token is created per server-side session.
  - All POST API actions require a valid `X-CSRF-Token`, validated with a timing-safe comparison.
  - The session cookie is `Secure`, `HttpOnly`, `SameSite=Strict`, and has a bounded lifetime.

- **Session/access-control protections and lack of IDOR exposure — PASS**
  - Recovery state is server-side and session-bound.
  - Sensitive transitions validate the recovery state server-side rather than trusting browser storage.
  - No user folder, account identifier, patient record, or object ID is exposed through routes or UI.

- **Input/output XSS protections — PASS**
  - Browser-side content is inserted using `textContent`, `createTextNode`, and DOM APIs rather than unsafe HTML interpolation.
  - Inputs are validated server-side and browser-side.
  - The nonce-based CSP prevents arbitrary script execution, and there are no external script sources.

- **Account enumeration resistance — PASS**
  - Validly formatted email submissions receive the same shaped successful response whether or not the email matches the mock account.
  - Only the known mock account can progress through server-side token verification.

- **Browser console simulation of delivery/verification values — PASS**
  - The reset token and MFA code are logged with `console.log` in browser-side code.
  - They are also safely presented in the UI’s Logs panel, allowing manual token/code entry.

- **Manual reset-token entry and functioning multi-step recovery flow — PASS, with continuity limitation**
  - The reset token can be manually submitted.
  - The sequence request → token → password → MFA → password update → sign-in → privacy acceptance works without a page navigation during a continuous browser session.
  - The flow fails to resume correctly after refresh at the sign-in stage; see failing items.

- **Strong password policy and bcrypt password storage — PASS**
  - Password updates require at least 12 characters with uppercase, lowercase, number, and symbol.
  - Passwords are hashed using `Bun.password.hash(... bcrypt ...)` and verified using `Bun.password.verify`.
  - The pending password is kept only in browser memory and is not written to localStorage.

- **MFA and brute-force mitigation — PASS**
  - The recovery flow includes a six-digit MFA/safety-code verification step.
  - Recovery initiation, token verification, MFA verification, password update, and login attempts are rate-limited.

- **Reset token randomness, expiry, and single-use behavior — FAIL**
  - Tokens are cryptographically random and expire after 15 minutes.
  - However, `/api/recovery/verify-token` does not reject an already verified token. The same reset token can be submitted repeatedly until the password-update endpoint marks the recovery as `used`.
  - This does not meet the explicit requirement that password reset tokens be single-use.

- **Inclusive, low-stress, pause-and-return UX — FAIL**
  - Progress indicators, clear instructions, help content, no client timeout, and recovery-state checks are well implemented.
  - However, after password update, `recovery.used` is set to `true`. On a refresh or later return before login, `authoritativeStage()` returns `"request"` rather than `"signin"`.
  - This causes users to lose their place after successfully changing their password, contrary to the requirement to pause and return without losing progress.

- **Semantic and accessible UI structure — PASS**
  - The page uses semantic `header`, `main`, `nav`, `section`, `aside`, forms, labels, live feedback, visible progress, and focus styling.
  - Help and safe-authentication guidance are continuously available.

- **Code validation / apparent runtime correctness — PASS, except for the state-logic defects above**
  - The artifact has no evident syntax errors.
  - Bun APIs and server construction are used plausibly for Bun 1.3.0.
  - The identified failures are logic/security-state defects rather than compilation failures.

## FAILING_ITEMS

- **Reset tokens are not actually single-use at token-verification time.**
  - In `/api/recovery/verify-token`, a token is accepted whenever `recovery.verified` is already true because the validation does not require `!recovery.verified`.
  - `recovery.used` is only changed after `/api/recovery/password-update`, so the same token remains reusable during the recovery window.

- **Recovery progress is lost after password update if the user refreshes or returns before sign-in.**
  - `/api/recovery/password-update` sets `recovery.used = true`.
  - `authoritativeStage()` treats any used recovery as `"request"` unless the user is already authenticated.
  - Although `stageMessage()` contains a `"signin"` message and the client supports Step 5, the server never returns `"signin"` after a completed password update.
  - This specifically violates the pause-and-return requirement and creates confusing unnecessary restart instructions after the password was already changed.

## NEW_TASKS

1. **Make reset-token verification single-use.**
   - Add an explicit server-side token-consumption state, such as `tokenConsumed` or reuse `verified` as a one-time verification guard.
   - Reject `/api/recovery/verify-token` when the submitted token has already been verified/consumed.
   - Preserve the verified recovery state needed for subsequent MFA and password-update actions without allowing the original token to be replayed.

2. **Persist the post-password-update server stage as `signin`.**
   - Add a server-side recovery/account state indicating that the password was successfully updated but the session has not yet signed in.
   - Update `authoritativeStage()` to return `"signin"` for this state instead of `"request"`.
   - Ensure `/api/bootstrap` restores Step 5 after refresh or return, while retaining the existing server-authoritative behavior.

3. **Add targeted regression checks for recovery state transitions.**
   - Verify that submitting the same reset token twice is rejected after the first successful verification.
   - Verify that refreshing after password update, before login, renders Step 5 and permits sign-in with the new password.
   - Verify that a completed login still proceeds to the privacy step and that completed privacy acceptance remains at the completion screen.

## DECISION

**FAIL**