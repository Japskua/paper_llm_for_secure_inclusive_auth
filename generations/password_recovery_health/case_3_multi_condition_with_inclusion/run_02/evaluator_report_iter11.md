## SUMMARY

The artifact is a valid single-file Bun/TypeScript implementation with a functional HTTPS SPA, CSRF-protected API requests, randomized hashed reset tokens, Argon2id password hashing, MFA, throttling, CSP nonces, and a clear step-by-step UI. However, it does not fully meet the inclusivity requirement to let users pause and return without losing progress: simulated recovery/MFA delivery values disappear on refresh/navigation while the server restores the user to steps that require those unavailable values. There is also a reset-token single-use race condition under concurrent password-reset requests.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun server and browser SPA**
  - The full server, HTML, CSS, and vanilla browser JavaScript are contained in `app.ts`.
  - No framework, external asset, build step, or external network request is used.

- **PASS — HTTPS and certificate use**
  - `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`.
  - Secure cookies use `Secure`, `HttpOnly`, `SameSite=Strict`, and the `__Host-` cookie prefix.
  - HSTS is returned on responses.

- **PASS — CSRF protections**
  - Sensitive POST endpoints require an existing session, an exact same-origin `Origin` header, and a session-specific `X-CSRF-Token`.
  - CSRF values are generated per server session and embedded only into the rendered same-origin page.

- **PASS — Access control for protected actions**
  - Privacy acceptance and appointment booking require a completed MFA-authenticated session.
  - Appointment confirmation also requires privacy acceptance.
  - No private account identifiers are returned by the API.

- **PASS — Reset-token handling**
  - Reset tokens are cryptographically random, stored only as SHA-256 hashes, time-limited, and invalidated after password replacement.
  - Manual reset-token entry is supported.
  - The simulated recovery link remains same-origin and does not mutate state on GET; confirmation occurs through a CSRF-protected POST.

- **FAIL — Reset token is not reliably single-use under concurrent requests**
  - In `replacePassword`, two concurrent requests attached to the same valid reset token can both pass `invalidRecord(current)` before either request sets `record.used = true`.
  - Both can then asynchronously hash passwords and overwrite the account password. The last request wins.
  - This violates the requirement that reset tokens be single-use.

- **PASS — Password and login security**
  - Passwords are stored using `Bun.password.hash(..., { algorithm: "argon2id" })`.
  - Password policy requires at least 12 characters plus uppercase, lowercase, number, and symbol.
  - Login attempts are throttled after five failed attempts.
  - Reset token confirmation, recovery identity verification, and MFA checks also include failure limits/lockouts.

- **PASS — MFA implementation**
  - A post-login MFA flow requires both a six-digit demonstration code and a separate possession value.
  - MFA state expires and is required before accepting privacy conditions or booking the appointment.

- **PASS — XSS and injection defenses**
  - Browser UI uses `textContent`, `replaceChildren`, and DOM APIs rather than injecting user-controlled HTML.
  - The recovery link is parsed, constrained to same-origin `/`, and created as a DOM anchor.
  - CSP uses per-page nonces and denies all scripts/styles except nonce-authorized inline application code.

- **PASS — Secure headers and error handling**
  - CSP, HSTS, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and cache-prevention headers are configured.
  - Generic server errors are returned without stack traces or debug output.

- **PASS — Clear, low-distraction recovery flow**
  - The UI provides numbered progress, one primary step at a time, clear next-step buttons, live feedback, a help panel, and a safety reminder about not sharing passwords/codes.

- **FAIL — Pause/return support loses required simulated delivery values**
  - The application says progress remains in the browser session and restores the user’s workflow stage via `/api/state`.
  - However, the recovery identity value, MFA code, and MFA possession value are only displayed in the initial page’s in-memory log area and browser `console.log`.
  - On a page refresh or navigation, the app may restore the user directly to the identity or MFA stage, but the required simulated delivery values are no longer shown in the UI and are not re-logged from stored browser state.
  - For example, after a successful recovery-token confirmation, refresh restores `identity`, but the recovery identity value cannot be recovered through the UI. The user must abandon progress and start/recover through an unclear alternate path.
  - This fails the requirement to allow users to pause and return without losing progress, especially for the ADHD-focused low-stress workflow.

- **PASS — Help and phishing guidance**
  - Help is accessible from the header at every stage.
  - The UI explicitly tells users that staff will never request passwords or recovery codes by email, text, or phone.

## FAILING_ITEMS

- Reset-token consumption is not atomic. Concurrent calls to `/api/recovery/password` can use the same valid reset record before `record.used` is set, allowing multiple password replacements from one reset token.

- Simulated recovery and MFA delivery values are not persisted or restored in the browser UI. A refresh/navigation can restore the workflow to a step requiring a code that the user can no longer access, contradicting the stated pause-and-return behavior.

## NEW_TASKS

1. Make password-reset token consumption atomic in `replacePassword`.
   - Add a per-token `inProgress`/reserved state or mutex before any asynchronous password hashing.
   - Reject concurrent password-change attempts for a reserved token.
   - Mark the token permanently used only after a successful password update, and safely clear the reservation if hashing/update fails.

2. Persist and restore simulated delivery information for the active browser session.
   - Store the recovery identity value and MFA mock values in `sessionStorage` when they are returned by the API.
   - Re-render and `console.log` the applicable simulated delivery values when the page initializes or restores a recovery/MFA stage.
   - Clear those session-storage values after successful identity/MFA completion, expiration, or when a new recovery/login flow replaces them.

3. Ensure resumed recovery/MFA stages always provide a user-visible recovery path.
   - If a required mock value is unavailable after restoration, show a clear “request a new recovery instruction” or “sign in again to receive a new safety code” action rather than leaving the user at an unusable form.

## DECISION

**FAIL**