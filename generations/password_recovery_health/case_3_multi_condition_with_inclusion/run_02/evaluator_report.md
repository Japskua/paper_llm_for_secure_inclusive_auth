## SUMMARY

The artifact is a single `app.ts` Bun application with a functional password-recovery, login, MFA, privacy acceptance, and appointment-confirmation flow. It has strong structural security measures including TLS, CSP nonces, CSRF validation, secure cookies, Argon2id hashing for changed passwords, token expiration/single-use handling, and output-safe client rendering. However, it does not fully meet the authentication/security requirements because it embeds a plaintext initial password in source code and its recovery-request/token-confirmation throttling can be bypassed by creating new sessions.

## FUNCTIONAL_CHECK

- **Single-file Bun server and SPA implementation — PASS**
  - The server, HTML, CSS, and vanilla browser JavaScript all exist in `app.ts`.
  - It uses `Bun.serve` directly and does not require a bundler, framework, compiler, external asset, or network request.

- **HTTPS, TLS certificate use, and security headers — PASS**
  - Bun TLS is configured with `certs/cert.pem` and `certs/key.pem`.
  - Responses include HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and cache-prevention headers.
  - The CSP uses a per-page nonce for the inline style and script blocks.

- **CSRF protection and sensitive-route access control — PASS**
  - State-changing routes use the `sensitive()` helper.
  - `sensitive()` requires an active session, exact same-origin `Origin` header, and the session-specific CSRF token.
  - The session cookie is `Secure`, `HttpOnly`, `SameSite=Strict`, has `Path=/`, and uses the `__Host-` prefix.
  - Privacy acceptance and appointment booking additionally require completed MFA and the correct workflow state.

- **XSS and injection defenses — PASS**
  - User-provided values are validated server-side and are not interpolated into HTML.
  - Browser feedback and mock logs use `textContent`, not `innerHTML`.
  - Browser-side links are constrained to same-origin recovery URLs and are created with DOM APIs.
  - No untrusted scripts or external scripts are loaded.

- **Secure recovery tokens and manual/link verification flow — PASS**
  - Reset tokens are cryptographically random, hashed before server storage, short-lived, and marked single-use after password replacement.
  - Reset links are non-mutating GETs; token confirmation occurs through a CSRF-protected POST.
  - The reset token can be entered manually.
  - Mock reset values are returned to the UI and logged in the browser console as required for testing.
  - The recovery flow progresses through token confirmation, a separate identity value, password replacement, login, MFA, privacy acceptance, and appointment confirmation.

- **Password policy and password hashing for changed passwords — FAIL**
  - New passwords are checked for length, upper/lowercase letters, numbers, and symbols.
  - Password replacements are stored with Argon2id.
  - However, `provision()` contains a hard-coded plaintext password: `"Initial!HospitalPassword9"`.
  - This conflicts with the requirement that passwords must never be stored in plaintext. Even though it is hashed during provisioning, the password is still present in application source.

- **Login and recovery brute-force protection — FAIL**
  - Login failures are tracked by account hash and lock after five failures, which is good.
  - Recovery identity verification is associated with the reset record and locks after repeated failures, which is also good.
  - However, recovery issuance throttling (`recoveryIssues`) is keyed by `session.id:accountKey`, and reset-token confirmation failures are stored only in the current session.
  - An attacker can simply create a new session by clearing cookies or using a fresh client and bypass both controls. This permits automated repeated recovery requests and unlimited reset-token guesses across new sessions.

- **MFA implementation — PASS**
  - The flow requires a password plus a six-digit demonstration code plus a separate possession value.
  - MFA is short-lived, protected by failure counters/temporary lockouts, and is required before privacy acceptance or appointment confirmation.
  - The code and possession value are intentionally simulated and browser-logged per the mock-delivery requirement.

- **ADHD-inclusive, low-stress UX — PASS**
  - The interface presents a visible, numbered recovery progress sequence.
  - Each stage has clear feedback, explicit “Continue” actions, and avoids forced navigation during ordinary completion.
  - Help is persistently available from the header and includes a clear anti-phishing reminder.
  - Recovery/MFA mock values are retained in `sessionStorage` to support reload/resume during the active browser session.

- **No external network calls and safe navigation/redirect behavior — PASS**
  - Browser requests are same-origin API calls only.
  - No external URLs are fetched.
  - Recovery-link rendering validates that the target remains the same-origin root recovery path and rejects protocol-relative or external paths.

- **Error handling and production information exposure — PASS**
  - The server catches unexpected errors and returns generic messages rather than stack traces.
  - Unknown routes return a generic 404 response.
  - The API does not expose account records, usernames, password hashes, or other account data.

## FAILING_ITEMS

- **Plaintext password embedded in source code**
  - `provision()` includes the literal password `"Initial!HospitalPassword9"`.
  - This violates the requirement that passwords must be hashed and never stored in plaintext.

- **Recovery request throttling is session-bypassable**
  - `issueAllowed()` keys its rate limit by `${session.id}:${accountKey}`.
  - A user can obtain a new session and make another three recovery requests immediately.
  - This enables repeated reset-instruction generation and does not provide durable throttling against automated recovery abuse.

- **Reset-token confirmation lockout is session-bypassable**
  - `resetConfirmationFailures` is stored on the session object.
  - An attacker can reset the failed-attempt counter by using a new browser session.
  - This does not fully satisfy the requirement that automated guessing attempts be throttled or blocked.

## NEW_TASKS

1. Replace the hard-coded plaintext initial password in `provision()` with a precomputed Argon2id password hash, or remove the fixed bootstrap password entirely and provision test accounts using hashes only.

2. Replace the recovery-instruction rate-limit key with a durable server-side key that cannot be reset by obtaining a fresh session, such as a combination of normalized account hash and a server-controlled client rate-limit bucket.

3. Move reset-token confirmation failure tracking from the session into server-side token/global attempt tracking, and enforce a rate limit for invalid token submissions that persists across newly created sessions.

## DECISION

**FAIL**