## SUMMARY

The artifact is a well-structured single-file Bun application with a functional password recovery, reset, MFA, privacy acceptance, and appointment confirmation flow. It uses HTTPS/TLS, secure headers, server-side session state, CSRF validation, bcrypt password hashing, route authorization, and DOM-safe client rendering. However, it does not fully meet the security and inclusivity requirements because login throttling is only session-scoped and can be bypassed by obtaining new sessions, recovery behavior can reveal whether an identifier belongs to the demo account, and progress is discarded after the fixed session lifetime.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no build tooling**
  - The entire server, HTML template, CSS, and browser JavaScript are contained in `app.ts`.
  - It uses `Bun.serve()` directly and does not require bundlers, frameworks, packages, or external assets.

- **PASS — HTTPS/TLS is configured with the required certificate paths**
  - The Bun server uses:
    - `certs/cert.pem`
    - `certs/key.pem`
  - Requests not using HTTPS are rejected.

- **PASS — Secure response headers are configured**
  - HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and no-cache headers are present.
  - CSP uses a generated nonce for the application’s inline style and script blocks.

- **PASS — Session cookies are secure**
  - The session cookie is opaque, `HttpOnly`, `Secure`, `SameSite=Strict`, and scoped to `/`.
  - Session identifiers and CSRF tokens are generated using cryptographically secure random values.

- **PASS — CSRF protection is implemented for state-changing requests**
  - All POST endpoints require a valid session-specific CSRF token.
  - The browser includes the CSRF token through `x-csrf-token`.
  - Cross-site requests are additionally constrained by `SameSite=Strict` cookies and lack of permissive CORS headers.

- **PASS — Sensitive actions enforce server-side authorization**
  - Password reset requires a verified recovery token.
  - Privacy acceptance requires authentication.
  - Appointment confirmation requires both authentication and privacy acceptance.
  - Browser route changes alone cannot grant access because protected API endpoints validate server-side state.

- **PASS — Password reset tokens are random, hashed, short-lived, and single-use**
  - Tokens are generated with `randomBytes`.
  - Only SHA-256 hashes of reset tokens are stored.
  - Tokens expire after ten minutes.
  - A reset token is marked used after a successful password update.
  - Token verification attempts are limited and locked after repeated failures.

- **PASS — Passwords are hashed with bcrypt and a strong password policy is enforced**
  - Passwords are stored using `Bun.password.hash(... algorithm: "bcrypt")`.
  - Reset passwords require 12–128 characters with uppercase, lowercase, numeric, and symbol characters.
  - Password confirmation is required.

- **PASS — MFA is implemented**
  - The flow requires a second verification step after both password reset and regular login.
  - MFA codes expire and have attempt limits.
  - Mock codes are logged in the browser console and visible practice log as required.

- **PASS — Manual recovery-code entry and simulated-link completion both work**
  - Recovery codes may be entered manually.
  - The simulated recovery-link button uses the delivered mock token.
  - Both paths call the same server-side recovery verification endpoint.

- **PASS — XSS protections are generally sound**
  - User-controlled values are not inserted with `innerHTML`.
  - UI text is inserted using `textContent`.
  - Identifier values, passwords, codes, and tokens are not reflected into the page.
  - Input formats are validated server-side.

- **PASS — The UX is structured and ADHD-conscious in several areas**
  - The interface provides a visible progress indicator.
  - Each step has a focused, short explanation and one primary next action.
  - Help and safety guidance is present on every screen.
  - There are no visible countdown timers or abrupt client-side page loads.
  - The mock activity panel helps users retrieve recovery/MFA values without leaving the task.

- **FAIL — Login throttling/account lockout can be bypassed**
  - Login failure tracking is stored only in `session.loginAttempts` and `session.loginLockedUntil`.
  - An attacker can obtain a new session cookie and continue password guessing without being locked out.
  - This does not satisfy the requirement that automated guessing attempts be throttled or blocked, nor the requirement for effective login attempt throttling/account lockout.

- **FAIL — Recovery initiation leaks whether an identifier is the recoverable demo account**
  - For `care-demo-4821`, `/api/recovery/initiate` returns `mockToken` and creates a valid recovery state.
  - For other syntactically valid identifiers, no token is returned and no recovery state is created.
  - The browser then behaves differently:
    - known identifier proceeds to `#verify`;
    - unknown identifier is redirected back to `#home`.
  - This is an observable account-enumeration signal despite the generic textual response.

- **FAIL — Progress is not retained if the session expires**
  - Session state is held only in memory and expires after eight hours.
  - The cookie also expires after eight hours.
  - Once expired, the user loses recovery, MFA, privacy, and appointment progress and is returned to the start.
  - This conflicts with the inclusivity requirement to let users pause and return without losing progress and to avoid session timeouts.

- **PASS — No external network calls or open redirects are present**
  - Client calls are same-origin API calls only.
  - No user-controlled redirect targets or outbound URLs are used.

- **PASS — Error handling does not expose stack traces or debug details**
  - The server catches unexpected failures and returns a generic production-safe message.
  - Unknown routes return generic JSON errors.

## FAILING_ITEMS

- Login brute-force protection is only session-specific. Clearing/replacing the session cookie bypasses the five-attempt lockout.
- Recovery initiation has account-enumeration behavior:
  - only the recognized identifier receives `mockToken`;
  - only the recognized identifier gets a valid recovery state;
  - route resolution visibly differs for recognized versus unrecognized identifiers.
- User progress is lost when the eight-hour session/cookie timeout occurs, contrary to the pause-and-return requirement.

## NEW_TASKS

1. Implement login throttling and lockout state that is not scoped solely to a browser session.
   - Track failed login attempts by normalized identifier/account and, where appropriate, client IP.
   - Apply a server-side lockout/rate limit that remains effective when a caller creates a new session.
   - Return generic login failure messages regardless of whether the account exists.

2. Remove observable recovery-account enumeration from the recovery initiation flow.
   - Ensure all syntactically valid identifiers receive the same response shape and the same next-screen behavior.
   - Do not conditionally expose `mockToken` only for a recognized account through the recovery-initiation response.
   - Preserve the required browser-console mock delivery in a way that does not expose whether an entered private identifier exists.

3. Preserve pause-and-return progress without relying on an eight-hour session expiry.
   - Remove the fixed session expiry for saved recovery-flow progress, or persist a minimal protected recovery-progress record that can be restored safely.
   - Keep security-sensitive reset and MFA tokens short-lived as required, but allow the user to return and restart only the expired security verification step rather than losing all task orientation and progress.

## DECISION

**FAIL**