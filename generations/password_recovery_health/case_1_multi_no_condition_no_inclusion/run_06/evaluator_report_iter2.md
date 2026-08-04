## SUMMARY

The artifact is a single `app.ts` Bun application with a functional browser-rendered recovery UI, TLS setup, CSRF protections, secure cookies, CSP/security headers, bcrypt password hashing, rate limiting, mock MFA, and browser-console simulated delivery logs. However, it has security and functional gaps around reset-link usability and reset authorization lifecycle, so it does not fully meet the requirements.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun server and vanilla SPA implementation**
  - The server, HTML, CSS, and browser JavaScript are contained in one `app.ts`.
  - It uses Bun directly and has no frameworks, build tools, external assets, or external network requests.

- **PASS — HTTPS and supplied TLS certificate usage**
  - The Bun HTTPS listener uses `certs/cert.pem` and `certs/key.pem`.
  - The application fails closed when certificate files are absent.
  - A separate HTTP listener redirects to a fixed `https://localhost:<port>` destination.

- **PASS — Security headers and secure session cookie**
  - HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, permissions policy, COOP/CORP, and no-store caching are configured.
  - The session cookie is `HttpOnly`, `Secure`, `SameSite=Strict`, scoped to `/`, and has a finite lifetime.

- **PASS — CSRF protection for sensitive operations**
  - Each server-side session receives a cryptographically random CSRF token.
  - State-changing API endpoints require the token in `X-CSRF-Token`.
  - Session state is server-side and request-controlled IDs are not accepted for authorization.

- **PASS — XSS protections in the rendered UI**
  - Dynamic UI values are inserted using `textContent` and DOM APIs rather than `innerHTML`.
  - User-controlled values are validated server-side and client-side.
  - CSP uses a per-page nonce for the known inline style and script blocks.

- **PASS — Recovery identifier privacy / anti-enumeration behavior**
  - Recovery responses use a generic message regardless of account existence.
  - The UI does not display usernames, patient records, folders, or other private identifiers.

- **PASS — Reset token randomness, format, expiry, and verification throttling**
  - Tokens are generated with cryptographic randomness.
  - Tokens are short-lived (10 minutes), opaque, and validated against an allowlisted format.
  - Verification attempts are rate-limited, and token attempts are capped.

- **FAIL — Recovery link is not reliably functional as a password-reset link**
  - Reset tokens are bound to the session that requested them: `state.sessionId !== auth.session!.id` causes verification failure.
  - The simulated link contains only `?token=<token>`. If opened in a fresh browser, another browser profile, or a normal email-link scenario, the user receives a new session and cannot use the token.
  - A password recovery link must work as an independently usable token-based verification mechanism, while still protecting against CSRF for state-changing follow-up actions.

- **FAIL — Password reset authorization remains usable after the reset token has been consumed**
  - `apiVerifyToken()` marks the token as `used`, but it sets `session.resetVerified = true`.
  - `apiPassword()` does not check whether a password has already been replaced and never clears `resetVerified`.
  - Therefore, the same authenticated recovery session can call `/api/password` repeatedly and replace the password multiple times without requesting or verifying another recovery token.
  - This weakens the required single-use reset-token behavior and permits unintended sensitive actions after the intended recovery step is complete.

- **PASS — Password policy and password hashing**
  - Passwords require at least 12 characters, upper/lowercase letters, a number, and a symbol, with no whitespace.
  - Passwords are hashed using Bun bcrypt before being stored in session state.
  - Plaintext passwords are not retained in server variables after request completion.

- **PASS — MFA simulation and brute-force throttling**
  - MFA is required after password replacement before privacy acceptance.
  - The deterministic test MFA code is delivered through browser logging.
  - MFA attempts are throttled.

- **PASS — Privacy-condition acceptance access control**
  - Privacy acceptance requires server-side MFA completion and an explicit accepted boolean.
  - No user or patient identifier is accepted from the client to authorize that action.

- **PASS — Browser-console simulated delivery**
  - Recovery token/link and MFA test code are logged using browser-side `console.log`.
  - The code also provides a visible local Logs panel for testing.
  - Manual code entry is supported.

- **FAIL — Malformed cookies can cause an uncaught exception**
  - `parseCookies()` calls `decodeURIComponent()` without handling malformed percent-encoding.
  - A request containing an invalid cookie value such as `recovery_session=%` can throw a `URIError`.
  - This can produce a server error and conflicts with the requirement to avoid exposing debug information or stack traces in production.

## FAILING_ITEMS

- Recovery tokens are tied to the original browser session, so a simulated reset link is not usable when opened outside that original session.
- A verified recovery session can repeatedly invoke `/api/password` and replace the password after the token has already been consumed.
- Malformed cookie encoding can throw from `decodeURIComponent()` and is not safely handled.

## NEW_TASKS

1. Update the recovery-link/token flow so a valid token in `?token=` can establish a restricted recovery-verification session when opened in a new browser session, while retaining CSRF enforcement for subsequent POST requests.
2. Make password-reset authorization single-use: after a successful password update, clear or consume `resetVerified` and reject further `/api/password` calls unless a newly issued token is verified.
3. Harden cookie parsing by wrapping `decodeURIComponent()` in error handling and ignoring malformed cookie values rather than throwing.
4. Add a top-level safe error response strategy so unexpected request errors return a generic non-debug response with secure headers rather than exposing server exception details.

## DECISION

FAIL