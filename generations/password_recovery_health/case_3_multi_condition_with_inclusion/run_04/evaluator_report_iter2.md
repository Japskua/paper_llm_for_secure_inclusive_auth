## SUMMARY

The artifact is a single-file Bun HTTPS SPA with a generally strong implementation of secure headers, CSP nonces, CSRF protection, server-backed session state, random reset tokens, Argon2id password hashing, password policy enforcement, MFA, accessible step-by-step UI, and browser-console simulated delivery logs. However, it does not fully meet the security and recovery-flow requirements because recovery-code and approved-channel guessing are not throttled, and error paths can leave users stuck in a server recovery state with no supported way to restart the flow. MFA lockout also leaves the user without a usable recovery path. Therefore, the artifact cannot be accepted as-is.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application / no build tooling**
  - The complete Bun server, HTML, CSS, and client-side vanilla JavaScript are contained in `app.ts`.
  - It uses no framework, bundler, compiler, CDN, or external assets.

- **PASS — HTTPS and certificate usage**
  - The server checks for `certs/cert.pem` and `certs/key.pem`.
  - `Bun.serve()` is configured with TLS and the listener is HTTPS-only.
  - Session cookies use the `Secure` attribute.

- **PASS — Secure response headers and CSP**
  - Responses include HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, restrictive `Referrer-Policy`, restrictive `Permissions-Policy`, and no-cache headers.
  - The HTML response has a nonce-based CSP with `default-src 'none'`, nonce-limited scripts/styles, `form-action 'self'`, `base-uri 'none'`, and `frame-ancestors 'none'`.

- **PASS — CSRF protection for state-changing requests**
  - A random CSRF token is created per server session.
  - State-changing API requests require both an exact same-origin `Origin` header and a valid `X-CSRF-Token`.
  - Cookies use `SameSite=Strict`, `HttpOnly`, and `Secure`.

- **PASS — Reset token security**
  - Reset tokens are generated with `randomBytes`, are high entropy, stored only as SHA-256 hashes server-side, expire after 15 minutes, and are invalidated after password change.
  - Tokens are not predictable and are not embedded in server-rendered HTML.
  - The user can submit a token manually in addition to using the generated verification link.

- **PASS — Password security and login protection**
  - New passwords have a clear strong-password policy: at least 12 characters, uppercase, lowercase, number, symbol, no spaces, and maximum length.
  - Passwords are hashed using `Bun.password.hash(..., { algorithm: "argon2id" })`.
  - Login uses `Bun.password.verify`.
  - Login failures are throttled with a five-failure lockout for ten minutes.

- **FAIL — Recovery verification guessing is not throttled or blocked**
  - `/api/recovery/channel` accepts unlimited attempts at the six-digit approved-channel code.
  - `/api/recovery/verify` accepts unlimited reset-token guesses for an active recovery session.
  - The requirement explicitly states that automated guessing attempts must be throttled or blocked. Random reset-token entropy is good, but it does not replace rate limiting for the six-digit channel confirmation code or verification endpoint.

- **FAIL — Incorrect recovery code can make the UI unusable and prevents a supported restart**
  - If a user enters an incorrect recovery code, `/api/recovery/verify` returns `invalidRecovery: true`, even though the server-side recovery token remains valid and the session remains in `recovery`.
  - The client then calls `cleanStored()`, removes the reset token from browser storage, returns the user to the Start view, and tells them the recovery step is unavailable.
  - The Start view submits to `/api/recovery/start`, but that endpoint only accepts sessions in `anonymous` or `channel`; the session is still in `recovery`, so the user cannot actually restart.
  - Refreshing restores the `delivery` view, but the client-side delivery log and stored token were removed. The user may be unable to continue unless they independently retained the token.
  - This violates the forgiving, low-stress, pause-and-return recovery UX requirements.

- **FAIL — MFA lockout has no recovery route or clear lockout feedback**
  - After more than five MFA submissions, `session.mfaAttempts > 5` makes all future MFA attempts fail permanently for that session.
  - The session remains at stage `mfa`, the UI remains on the MFA view, and there is no button to return to sign-in, start a new MFA challenge, or restart recovery.
  - The generic error message does not tell the user that the MFA challenge has been locked or what safe next step to take.
  - This conflicts with the requirements for clear feedback, forgiving progression, and easy access to help/recovery options.

- **PASS — XSS and input/output safety**
  - Dynamic client content is built using DOM APIs and `textContent`/text nodes rather than unsafe `innerHTML`.
  - User data is not reflected into the DOM as HTML.
  - Server-side input validation is present for email addresses, tokens, passwords, and one-time codes.
  - No user-controlled redirect URL is accepted.

- **PASS — No IDOR/private data exposure in API responses**
  - API responses do not expose user IDs, account records, course folders, patient data, or stored password hashes.
  - Session state remains server-side and is keyed by opaque random session IDs.

- **PASS — MFA implementation and anti-phishing guidance**
  - The login flow requires a second one-time verification step before authentication.
  - Simulated MFA delivery is logged in the browser console as required for testing.
  - The help content clearly warns users not to share passwords or recovery codes and not to trust unexpected requests.

- **PASS — Inclusive, structured UI**
  - The UI has visible progress steps, explicit “Next step” guidance, consistent language, accessible focus styling, a skip link, semantic forms/labels, help access, and no countdown/session-time pressure.
  - The server-backed state restoration approach is appropriate in principle.

- **PASS — Internal recovery and help links function**
  - The simulated verification link routes to `/recovery/verify?token=...`.
  - The token is read from the URL and placed in session storage for verification.
  - The help links and footer help route render the help screen.

## FAILING_ITEMS

- Recovery channel confirmation (`/api/recovery/channel`) has no attempt counter, throttle, temporary lockout, or rate limiting. The deterministic six-digit channel code can be brute-forced through repeated requests.

- Reset-token verification (`/api/recovery/verify`) has no failed-attempt limit or throttling. Requests can be repeatedly submitted against an active recovery session.

- An invalid recovery-code submission is incorrectly treated by the client as a permanently invalid/expired recovery state. It deletes locally stored progress and the token even though the server still has an active `recovery` session.

- After the invalid recovery-code path, the Start form cannot restart recovery because the server still has the session in `recovery`, while `/api/recovery/start` rejects that stage. The user is stuck unless they manually clear cookies or wait for session expiry.

- MFA challenge exhaustion permanently blocks the active session without transitioning to a safe state, clearing the challenge, providing an explanation, or offering an actionable route back to sign-in/recovery.

## NEW_TASKS

1. Add server-side failed-attempt tracking and throttling/lockout for `/api/recovery/channel` and `/api/recovery/verify`, including a bounded number of attempts, a temporary lockout duration, and generic non-enumerating error responses.

2. Separate “wrong recovery code” responses from “expired, used, or unavailable recovery state” responses. Do not return `invalidRecovery: true` for a merely incorrect token while the token/session is still valid.

3. Update the client recovery-code error handling so an incorrect manually entered code preserves the active recovery state and lets the user correct and resubmit the code without deleting browser progress or the stored token.

4. Add a CSRF-protected server endpoint or explicit supported transition that abandons the current recovery attempt and safely returns the session to `anonymous`, then add a visible “Start recovery again” action for recovery-stage errors.

5. On MFA attempt-limit exhaustion, invalidate the active MFA challenge, transition the session to a recoverable state such as `resetComplete` or `anonymous`, and return a clear generic message with a supported UI action to sign in again or restart password recovery.

## DECISION

FAIL