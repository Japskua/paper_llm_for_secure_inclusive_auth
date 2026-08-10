## SUMMARY

The artifact is a single-file Bun HTTPS SPA with a generally coherent mobile MFA flow, TLS configuration, security headers, session cookies, CSRF checks on authenticated MFA mutations, QR rendering, and browser-side mock logging. However, it does not meet key MFA security requirements: OTP verification accepts any six digits, secrets and recovery codes are static and not protected at rest, there is no rate limiting or session timeout enforcement, and recovery codes are not logged in the browser as required. Several inclusivity and recovery-code usability requirements are also incomplete.  

## FUNCTIONAL_CHECK

- **Single `app.ts` artifact containing Bun server, HTML, CSS, and browser JavaScript — PASS**
  - The entire server and SPA template are contained in one file. No framework, bundler, external assets, or external network calls are used.

- **Bun serves HTTPS using the supplied certificate paths — PASS**
  - `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`.
  - The server is intended to run at `https://localhost:3000`.

- **Mobile-responsive, legible UI — PASS**
  - The page includes a viewport meta tag, a constrained content width, large controls, clear focus styles, generous line height, and a reasonably readable font stack.

- **Plain-language, dyslexia-aware flow with no reading timer — PARTIAL / FAIL**
  - Short instructions and “Take your time. There is no reading timer.” are good.
  - However, help/hints are not available at every step, the visible diagnostic “Logs” panel adds clutter, and several actions provide no confirmation or recovery guidance.

- **One clear primary action per screen — PARTIAL / FAIL**
  - The main flow generally has a prominent primary button.
  - The setup screen presents both “Copy secret” and “I added it to my app” without clearly distinguishing the secondary action beyond styling. More importantly, there is no visible retry/re-request path after provisioning or verification errors.

- **QR code and manual authenticator-secret setup — PASS**
  - The provisioning endpoint returns an `otpauth://` URI and secret.
  - The UI renders a QR code and displays the secret for manual authenticator setup.
  - A copy button is provided for the secret.

- **Browser autofill / password-manager support — PASS**
  - Email, password, and OTP fields use suitable `autocomplete` attributes, including `autocomplete="one-time-code"` for OTP entry.

- **OTP delivery/provisioning/verification simulated with deterministic mock values — FAIL**
  - `/api/provision` returns a deterministic mock OTP value (`282760`) and it is logged in the browser.
  - However, `/api/verify-otp` accepts **any** six-digit value. It does not verify the deterministic mock code, a TOTP code, or any expected code at all.

- **OTP codes are single-use, time-bound, and high-entropy — FAIL**
  - The mock OTP is hard-coded and has no expiry.
  - It is never consumed; any six-digit number succeeds.
  - No one-time-use enforcement exists.

- **Retry, reveal/hide, and re-request support without penalty — FAIL**
  - Invalid OTP input can be retried, but no rate-aware retry design or clear retry control is provided.
  - The secret cannot be hidden after display.
  - There is no explicit way to re-request/re-provision the authenticator setup after leaving or failing a step.

- **Recovery codes are shown and can be securely saved — PARTIAL / FAIL**
  - Recovery codes are displayed after successful OTP verification.
  - There is no copy-all, download, print, or other practical save mechanism.
  - There is no confirmation that copying/saving occurred beyond a self-attestation button.
  - No recovery-code regeneration flow exists.

- **Mocks are logged in the browser console, including OTP and recovery codes — FAIL**
  - The OTP test value is logged through `console.log`.
  - The recovery-code array is returned to the UI but is not logged to the browser console. `save(c)` renders the codes but never calls `console.log`/`log` with `c`.

- **All internal navigation/actions function — PARTIAL / FAIL**
  - The visible sign-in → provision → verify → recovery → completion → logout flow is wired through client-side actions.
  - However, a page refresh after sign-in loses the in-memory client CSRF token and returns the user to sign-in even if the secure session cookie remains valid. The app does not restore authenticated state or provide an authenticated settings endpoint.

- **Server-side authorization and IDOR resistance on MFA endpoints — PASS**
  - Authenticated MFA operations require an active server-side session.
  - The server associates the session with the only account and rejects unauthenticated requests.
  - There are no client-supplied user IDs that could be manipulated for IDOR.

- **CSRF protection for authenticated state-changing MFA endpoints — PASS**
  - `/api/provision`, `/api/verify-otp`, and `/api/logout` require both same-origin `Origin` and the session-bound `X-CSRF-Token`.
  - The session cookie is `SameSite=Strict`.

- **CSRF protection for every state-changing endpoint — PARTIAL / FAIL**
  - `/api/signin` creates a server-side session but has no explicit CSRF validation.
  - While JSON content type and absent permissive CORS reduce practical browser form-CSRF risk, the stated requirement calls for CSRF protection on all state-changing requests.

- **Secure HTTP response headers and clickjacking protection — PASS**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and CSP `frame-ancestors 'none'` are configured.
  - The CSP uses a per-page nonce for inline script and style.

- **Restricted CORS and no verbose production errors — PASS**
  - No permissive CORS headers are configured.
  - The top-level server handler returns a generic 500 response rather than a stack trace.

- **Secure session cookie configuration — PASS**
  - The session cookie has `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, and a `Max-Age`.

- **Secure session lifecycle: rotation, idle/absolute timeout, logout invalidation — PARTIAL / FAIL**
  - A new session ID is created on successful sign-in and logout removes the session from the server map.
  - The server does not track or enforce idle timeout or absolute session expiration. Cookie expiry alone is insufficient because a stolen/otherwise submitted valid session ID remains accepted until manually removed or process restart.

- **No secrets, OTPs, backup codes, or session tokens exposed in logs, URLs, or errors — FAIL**
  - The provisioning response returns the OTP secret to browser JavaScript and renders it, which is appropriate only during setup, but the secret is hard-coded server-side.
  - The browser logs the mock OTP value.
  - The requirements explicitly require browser-console mock logging for test values, which conflicts with the security requirement prohibiting OTP/backup-code logging. Regardless, the implementation does not limit this test exposure to an explicitly isolated testing mode.
  - Recovery codes are also sent as plaintext response data and stored only in transient UI state, rather than being securely represented server-side.

- **OTP secret and backup codes generated securely and protected at rest — FAIL**
  - The OTP secret is a hard-coded constant: `JBSWY3DPEHPK3PXP`.
  - Recovery codes are a hard-coded array.
  - Neither is generated using a cryptographically secure RNG for each enrolment.
  - Neither is hashed or encrypted at rest; the implementation has no protected persistence model.

- **No browser persistence of secrets or tokens — PASS**
  - The code does not use `localStorage`, `sessionStorage`, IndexedDB, or non-HttpOnly cookies for session IDs, OTP secrets, or recovery codes.

- **Input validation and injection defenses — PARTIAL / FAIL**
  - OTP format is checked with `/^\d{6}$/`; client-rendered dynamic strings are escaped with `esc()`.
  - However, email and password input are not server-side validated for type, length, or format.
  - The generic JSON parser accepts arbitrary property types, and input-validation rules are incomplete.
  - There is no database, so parameterized-query compliance is not applicable to this implementation.

- **Open redirect prevention — PASS**
  - No redirect parameter or redirect behavior is implemented.

- **Rate limiting and lockout after failed verification attempts — FAIL**
  - There is no attempt counter, rate limit, cooldown, lockout, or audit handling for sign-in or OTP verification attempts.

- **Avoid account enumeration — PASS**
  - Failed sign-in uses one generic message for an invalid email/password combination rather than identifying which value was incorrect.

- **Code validity / direct browser execution — PARTIAL / FAIL**
  - The overall TypeScript and browser JavaScript structure is syntactically plausible for Bun and modern browsers.
  - However, the application is functionally faulty because its central OTP verification logic does not verify an OTP at all. This prevents acceptance even though the code can likely start.

## FAILING_ITEMS

- OTP verification accepts any six-digit input instead of validating the deterministic mock OTP or a simulated TOTP result.
- OTPs are neither time-bound nor single-use.
- No failed-attempt rate limiting, cooldown, or account/session lockout exists for OTP or sign-in attempts.
- OTP secret and recovery codes are hard-coded, reused across enrolments, and not cryptographically generated per user/enrolment.
- OTP secret and recovery codes are not encrypted or hashed at rest.
- Server-side session records have no enforced idle timeout or absolute timeout.
- `/api/signin` creates state without explicit CSRF validation.
- Email and password lack meaningful server-side type, length, and format validation.
- Recovery codes lack copy/download/print support, making secure storage unnecessarily difficult.
- Recovery codes are not logged in the browser console as explicitly required for mocks.
- The user cannot explicitly hide/reveal the setup secret or re-request/re-provision setup after an error.
- There is no easily available help/hint at every stage.
- The permanent visible “Logs” panel creates visual clutter and exposes diagnostic test information in the normal UI.
- Reloading after successful sign-in does not restore authenticated enrollment state and instead returns the user to the sign-in form.
- The conflicting requirement to log mock OTP/recovery values in the browser while never logging sensitive values needs an explicit test-mode design and strict separation from normal operation.

## NEW_TASKS

1. Replace the permissive OTP check with server-side validation against a per-enrolment deterministic mock OTP or a server-generated TOTP simulation value; reject all other values.
2. Store OTP challenge state in the authenticated session with an issuance timestamp, expiry, used flag, and attempt counter; invalidate it after successful verification.
3. Add server-side rate limiting and lockout/cooldown handling for failed sign-in and OTP verification attempts, with plain-language error messages stating when the user may retry.
4. Generate a new OTP seed and recovery-code set per enrolment using `crypto.getRandomValues`; remove the static `secret` and static recovery-code array.
5. Add protected server-side storage semantics: encrypt the OTP seed at rest and hash recovery codes before storage; only return plaintext recovery codes once when generated.
6. Add server-enforced session `createdAt` and `lastSeenAt` checks, with suitable absolute and idle expiration; delete expired sessions.
7. Apply an explicit anti-CSRF strategy to `/api/signin`, or document and implement a robust pre-authentication CSRF token flow compatible with the SPA.
8. Add strict server-side validation for JSON body shape and for email, password, and OTP types/lengths/formats before processing.
9. Add recovery-code save tools: copy all codes, download as a text file, and/or print, with a clear confirmation message and clipboard fallback handling.
10. Log the returned mock recovery-code set via `console.log` in the browser as required, but place all mock-secret logging behind a clearly labeled testing/demo mode so production behavior does not log secrets.
11. Add visible secondary controls to hide/reveal the setup secret, copy the provisioning URI/secret, restart provisioning, and return from verification to setup without penalty.
12. Add concise contextual help at each step and remove or hide the on-page debug log panel during the standard user flow.
13. Add an authenticated session-status/settings endpoint and client initialization logic so a refreshed page can restore the current enrolment step without requiring a redundant sign-in.
14. Clearly distinguish primary versus secondary actions on setup and recovery screens, preserving one visually dominant next action per step.

## DECISION

FAIL