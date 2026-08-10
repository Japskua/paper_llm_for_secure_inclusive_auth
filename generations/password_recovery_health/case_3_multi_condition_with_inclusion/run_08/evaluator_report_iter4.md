## SUMMARY

The artifact is a well-structured single-file Bun application with a functional recovery, reset, sign-in, MFA, privacy acceptance, and appointment-confirmation flow. It uses TLS, secure cookies, CSRF checks, CSP nonces, Argon2id hashing, server-side session state, and avoids rendering user-controlled input as HTML. However, it does not meet the security requirements fully: the simulated delivery-channel code is publicly shown and unthrottled, allowing unauthorized reset attempts for a known account identifier, and MFA retry limits can be bypassed by starting a new login/MFA cycle.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun server and SPA delivery**
  - The complete server, HTML template, CSS, and browser JavaScript are contained in `app.ts`.
  - It uses Bun directly and does not require a bundler, framework, compiler step, or external assets.

- **PASS — HTTPS and secure transport configuration**
  - The server is configured with `certs/cert.pem` and `certs/key.pem`.
  - Session cookies use `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, and the `__Host-` prefix.
  - HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and `Cache-Control: no-store` are configured.

- **PASS — CSRF protection**
  - A random CSRF token is generated per server-side session.
  - All POST `/api/` routes pass through `csrfValid()` before performing sensitive actions.
  - The token is compared using `timingSafeEqual`.

- **PASS — Server-side authorization and reset-token controls**
  - Privacy acceptance and appointment confirmation require an authenticated server-side session.
  - Reset tokens are random, SHA-256 hashed before storage, session-bound, expire after 15 minutes, and are marked single-use.
  - Reset completion derives the user only from server-side verified-reset state, preventing client-selected user IDs/IDOR.

- **FAIL — Password reset prevents unauthorized access**
  - The delivery-channel possession code (`864200`) is visibly rendered in the browser before possession is demonstrated.
  - Any user who knows or guesses an account email can request recovery, submit the public code, receive a valid reset token for an existing account, validate it, and reset that account password.
  - The generic reset-request response does not prevent account enumeration because `/api/reset-validate` returns `valid: true` only when the submitted token corresponds to an existing account.

- **FAIL — Brute-force protection is incomplete**
  - `/api/recovery-delivery` has no attempt throttling or lockout for its six-digit delivery code.
  - `/api/mfa` clears pending MFA state after five failed attempts, but a caller can immediately perform another successful password login and receive a new MFA attempt window. Therefore, the effective MFA code guessing limit is bypassable.
  - `mfaLockedUntil` exists in the session type but is never set before `clearMfaPending()` removes it.

- **PASS — Password hashing and password policy**
  - Passwords are hashed with Bun Argon2id (`Bun.password.hash(..., { algorithm: "argon2id" })`).
  - Passwords are not stored in plaintext.
  - The server enforces length, upper/lowercase, number, symbol, and no-space requirements.

- **PASS — Input/XSS handling**
  - User-controlled values are not interpolated into server HTML.
  - Browser-side dynamic feedback uses `textContent`, not unsafe HTML insertion.
  - API inputs are validated and request bodies are size limited.
  - CSP uses a per-response nonce and restricts script execution to the trusted application script.

- **PASS — Recovery flow and manual code submission**
  - The recovery process is functional: account identification, simulated delivery, manual token entry, token validation, password reset, login, MFA, privacy acceptance, and appointment confirmation.
  - The reset token is returned to the browser UI and logged through browser `console.log`.
  - Manual recovery-code submission works without requiring a link.

- **PASS — ADHD/inclusivity UX**
  - The UI provides visible step progress, clear “Next step” instructions, calm language, low-density screens, persistent browser progress, no displayed timeout pressure, a skip link, and easily accessible help/safe-authentication guidance.
  - The flow avoids unexpected navigation and gives feedback after actions.

- **PASS — No external calls or external assets**
  - The implementation does not make external network requests or load third-party resources.

- **PASS — Error handling / production exposure**
  - The server catches exceptions and returns a generic error response rather than stack traces or debug details.
  - No directory listings or private user records are exposed through the UI/API responses.

## FAILING_ITEMS

- **Public delivery-channel secret defeats reset authorization**
  - The recovery “delivery-channel access code” is hard-coded and displayed in the delivery UI:
    ```html
    <p class="code">864200</p>
    ```
  - The server accepts that code on `/api/recovery-delivery` and issues a usable reset token when the session previously requested recovery for an existing account.
  - This means the delivery check does not establish possession of a separate channel and permits an unauthorized password reset for any known account identifier.

- **Account-existence oracle remains available after the delivery step**
  - For a known identifier, the public delivery code produces a server-backed token that yields `{ valid: true }` from `/api/reset-validate`.
  - For an unknown identifier, the issued decoy token yields `{ valid: false }`.
  - An attacker can therefore distinguish whether an identifier corresponds to an account.

- **No rate limiting exists for delivery-channel code guesses**
  - `/api/recovery-delivery` accepts unlimited invalid six-digit code attempts.
  - This is a direct brute-force target because the code is only six digits.

- **MFA rate limiting/lockout can be bypassed**
  - Five failed MFA attempts only invalidate the current MFA-pending state.
  - The user can immediately start another login, pass the password check, and get a fresh five-attempt MFA window.
  - The declared `mfaLockedUntil` mechanism is not actually applied when the maximum failure count is reached.

## NEW_TASKS

1. Replace the publicly displayed recovery delivery code with a simulated second-channel authorization mechanism that is not exposed before authorization and cannot be used by an arbitrary recovery requester to reset a known account. Preserve the evaluation requirement by logging the delivered reset token in the browser only after the mock delivery authorization succeeds.

2. Prevent account enumeration through the recovery flow by ensuring that validation and completion responses do not reveal whether a recovery token belongs to an existing account, or by making the simulated delivery authorization unavailable to an unauthenticated requester who only knows an email address.

3. Add server-side rate limiting and temporary lockout for `/api/recovery-delivery` failures, keyed by an appropriate combination of session and client/network identity, with a bounded retry window.

4. Implement persistent MFA failure throttling/lockout across new login attempts. Set and enforce `mfaLockedUntil` (or use a server-side per-user/client MFA attempt record) so that restarting the login flow does not reset the MFA guessing limit.

## DECISION

FAIL