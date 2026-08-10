## SUMMARY

The artifact is a well-structured single-file Bun SPA with a functional recovery, password update, MFA, privacy-acceptance flow, HTTPS/TLS configuration, CSRF protection, security headers, rate limiting, and browser-side mock logging. The primary security defect is that a reset token is not consumed when it is successfully verified, despite the requirement that reset tokens be single-use. There is also a UX inconsistency in the pause flow: it says to use a “Resume recovery below” control that does not exist.

## FUNCTIONAL_CHECK

- **Single `app.ts` file containing Bun server, HTML, CSS, and vanilla browser JavaScript: PASS**
  - The entire implementation is contained in one TypeScript file and uses `Bun.serve` directly. No framework, bundler, compiler pipeline, or external assets are used.

- **Bun TLS server uses the supplied certificates: PASS**
  - The server is configured with `tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") }`.
  - Responses reject non-HTTPS request URLs and include HSTS.

- **Password recovery flow works end-to-end: PASS**
  - The UI supports requesting recovery, viewing simulated delivery, opening a recovery link, manually submitting a recovery code, setting a password, completing MFA, accepting privacy conditions, and reaching confirmation.
  - Internal recovery-link navigation (`/recovery-link?token=...`) is handled correctly.

- **Recovery code is returned to the UI and logged in the browser for mock testing: PASS**
  - `/api/demo/recovery-code` returns the mock code only after a recovery request.
  - The browser logs the code with `console.log` and renders it in the demonstration activity log.
  - Manual code submission is supported.

- **ADHD/inclusivity-oriented flow: PARTIAL / FAIL**
  - The step indicator, clear copy, help panel, no countdown, low-distraction layout, and persistent server-side session progress are good.
  - However, selecting “Pause and return later” does not actually present a “Resume recovery” action, even though the resulting message instructs the user to “use Resume recovery below.” This is confusing and does not fully meet the requirement for a clear pause-and-return experience.

- **CSRF protection on state-changing actions: PASS**
  - A random CSRF token is generated per server-side session.
  - Every POST API route requires `X-CSRF-Token`.
  - The session cookie is `HttpOnly`, `Secure`, and `SameSite=Strict`.

- **Access control and sensitive-route protection: PASS**
  - Password update requires a verified recovery flow.
  - MFA requires a pending authenticated flow.
  - Privacy acceptance requires an authenticated session.
  - No client-selected account IDs are used as direct object references.

- **XSS/injection protections: PASS**
  - The browser UI builds user-visible content with DOM APIs and `textContent`, rather than interpolating user input into HTML.
  - Inputs are validated server-side.
  - CSP uses a per-response nonce and blocks external script sources.
  - No external or untrusted scripts are loaded.

- **Security headers and production-safe errors: PASS**
  - HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and cache-control headers are configured.
  - Error responses do not expose stack traces or debug details.

- **Reset token randomness, expiry, and single-use semantics: FAIL**
  - Tokens are random (`randomBytes(32)`) and expire after 15 minutes.
  - However, successful `/api/verify` calls do **not** mark the reset record as used. The same valid reset token can be submitted repeatedly to `/api/verify` until a password is successfully saved.
  - The token is only marked used inside `/api/password`, which does not satisfy the explicit requirement that password reset tokens themselves be single-use.

- **Password security and policy: PASS**
  - New passwords are checked for length, uppercase, lowercase, digit, symbol, and no spaces.
  - Passwords are hashed using Bun’s bcrypt implementation and are not logged.
  - Password confirmation is required.

- **MFA and throttling: PASS for the stated deterministic mock design**
  - MFA is required before authentication is established.
  - The MFA code is a deterministic mock value and is surfaced in browser logs as required for testing.
  - Recovery, verification, password, login, MFA, and privacy actions are rate-limited.

- **No external network calls or open redirects: PASS**
  - Browser fetches are same-origin only.
  - The only generated navigation target is a server-created local path.

- **Code validity / direct Bun execution: PASS**
  - No apparent TypeScript syntax errors or incompatible build-time dependencies are present.
  - The implementation is suitable for direct execution by Bun, assuming the required certificate files are available at the specified paths.

## FAILING_ITEMS

- **Reset tokens are not strictly single-use.**
  - In `/api/verify`, a valid reset token is accepted and the session becomes recovery-verified, but `reset.used` remains `false`.
  - A caller can repeatedly submit the same reset token to `/api/verify` before a password save occurs.
  - This conflicts with the explicit requirement that password reset tokens be “single-use.”

- **The pause UX contains a nonexistent resume action.**
  - The pause message says: “use Resume recovery below.”
  - No resume control is rendered anywhere in the application.
  - The pause button also does not change the workflow state or clearly explain that the user should close the page and return later.

## NEW_TASKS

1. **Make reset verification consume the recovery token immediately.**
   - In `/api/verify`, after validating the reset record, set `reset.used = true`.
   - Create a separate, session-bound, short-lived password-reset authorization/grant that permits `/api/password` submissions without requiring the original token to remain reusable.
   - Require that grant in `/api/password`, expire it appropriately, and invalidate it after a successful password change.

2. **Implement a real, clear pause/resume UI state.**
   - When the user pauses, render a visible “Resume recovery” button or change the pause button to a resume action.
   - Ensure the resume action restores the server-derived workflow screen without requiring the user to infer what to do.
   - Remove or correct the current “use Resume recovery below” text unless that control is actually provided.

## DECISION

FAIL