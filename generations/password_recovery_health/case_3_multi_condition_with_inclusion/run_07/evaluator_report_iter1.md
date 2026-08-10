## SUMMARY

The artifact is a single-file Bun HTTPS SPA with a generally well-structured recovery flow, server-side session state, CSRF validation, bcrypt password hashing, random reset tokens, expiry, single-use verification, and accessible step-oriented UI. However, it does not fully meet the requirements: the CSP header is incorrectly named and therefore not enforced, normal successful sign-in cannot actually complete privacy acceptance, sensitive mock events are logged on the server rather than exclusively in the browser, and authentication throttling is only session-based and can be bypassed by obtaining a new session. No MFA or SSO is implemented.

## FUNCTIONAL_CHECK

- **Single `app.ts` deliverable containing Bun server, HTML, CSS, and vanilla client JavaScript — PASS**
  - The complete app is contained in one TypeScript file. It uses Bun directly with no framework, bundler, compilation pipeline, package dependency, or external asset.

- **Bun TLS server using the supplied certificate paths — PASS**
  - `Bun.serve()` is configured with `certs/cert.pem` and `certs/key.pem`, and the server only serves through the TLS configuration.

- **Password recovery flow supports request, code verification, manual code entry, new password, privacy acceptance, and confirmation — PASS**
  - A recovery code is generated, returned to the browser for testing, logged in the browser, can be typed manually into the verification form, is checked server-side, and leads to password update and privacy acceptance.
  - Reset tokens are cryptographically random, bcrypt-hashed at rest, tied to a session, expire after 15 minutes, and are marked used after successful verification.

- **All intended navigation links and pause/resume flow function — PASS**
  - Login, recovery, verification, password, privacy, pause, help, and confirmation routes render correctly in the SPA.
  - Pause/resume persists the recovery stage within the active server session and provides clear next-step guidance.

- **ADHD/inclusivity UX requirements — PASS**
  - The UI is structured as short steps, uses consistent wording, shows visible progress, has stable navigation, has no countdown timer, provides pause/resume, and exposes help/safe guidance throughout the recovery routes.

- **Normal sign-in can lead to accepting privacy conditions — FAIL**
  - `/api/login` returns `next: "/privacy"` after successful password authentication, but it does not create `session.recovery` or set its stage to `"privacy"`.
  - `/api/privacy-accept` requires both `session.authenticated` and `session.recovery?.stage === "privacy"`. Therefore, a user who signs in normally is shown the privacy page but receives a 403 error when trying to accept the conditions.

- **CSRF protections on sensitive requests — PASS**
  - A random CSRF token is generated per server session, inserted into the initial page, sent via `X-CSRF-Token`, and validated for all POST API actions.
  - Session cookies use `HttpOnly`, `Secure`, and `SameSite=Strict`.

- **Authorization/access control and IDOR protections — PASS**
  - Recovery records are server-side, opaque, tied to the requesting session ID, and are verified before password changes.
  - Password reset and privacy acceptance endpoints validate server-side stage and authentication state rather than trusting client routing.

- **XSS/input safety — PASS, except for missing enforced CSP**
  - User input is validated server-side and not interpolated into HTML.
  - Client-rendered dynamic values use `textContent` for the recovery token/log output.
  - There are no third-party scripts or external assets.
  - However, the CSP configuration itself is ineffective; see the security-header failure below.

- **Security headers and CSP are correctly configured — FAIL**
  - The response sets a header named `CSP`, but browsers enforce the header only when it is named `Content-Security-Policy`.
  - As written, the intended nonce-based script/style restrictions are ignored by browsers. This fails the explicit CSP/security misconfiguration requirement.

- **Password policy and password storage — PASS**
  - Passwords require at least 12 characters, upper/lowercase letters, a number, and a symbol.
  - Passwords are stored as bcrypt hashes through `Bun.password.hash()` and verified with `Bun.password.verify()`.

- **Authentication/recovery brute-force mitigation — FAIL**
  - Login lockout and reset-request throttling are stored only in the browser-session-associated server session.
  - An attacker can discard or avoid the `sid` cookie and create fresh sessions to bypass the five-attempt login lock and the three-request recovery limit.
  - The stated requirement calls for robust throttling, CAPTCHA, or account lockout after repeated failures.

- **MFA or SSO implementation — FAIL**
  - No MFA or SSO mechanism is implemented.
  - The reset code is part of the password recovery flow, but because it is immediately returned to the same browser session for testing, it is not a separate authentication factor for ordinary sign-in.

- **Mocks logged in the browser only — FAIL**
  - The browser correctly logs the recovery token using `console.log`.
  - However, the server also logs the recovery token and other simulated events using server-side `console.log`, including:
    - `[SIMULATED DELIVERY] Recovery code created...`
    - `[SIMULATED SECURITY] Password replaced...`
    - `[SIMULATED CONFIRMATION] Privacy conditions accepted...`
  - This violates the explicit requirement that all mocks use `console.log` in the browser, and logging recovery tokens server-side is additionally undesirable.

- **No external network calls or exposed private portal data — PASS**
  - There are no outgoing network requests other than same-origin API calls.
  - The UI does not expose account lists, usernames, folders, or patient data.

## FAILING_ITEMS

- The intended Content Security Policy is not enforced because the HTTP header is named `CSP` instead of `Content-Security-Policy`.
- A successful normal login navigates to `/privacy`, but privacy acceptance fails because the session has no recovery stage of `"privacy"`.
- Login and recovery-request throttling are tied only to the current session and are trivially bypassable by starting a new session or clearing cookies.
- MFA or SSO is not implemented.
- Simulated delivery/security/confirmation messages are logged by the Bun server, despite the requirement that mocks be logged in the browser. The server also logs the sensitive recovery code.

## NEW_TASKS

1. Replace the `CSP` response header key in `securityHeaders()` with the standards-compliant `Content-Security-Policy` header name, retaining the existing nonce-based policy.
2. Update the successful `/api/login` path so an authenticated user who has not accepted privacy conditions can validly enter the privacy-acceptance state, without requiring password recovery.
3. Implement throttling that cannot be bypassed merely by replacing the session cookie, such as bounded server-side counters keyed by normalized account identifier plus a request-origin/IP-derived key, with expiry and lockout windows.
4. Implement a simulated MFA or SSO step for normal authentication, with its deterministic test value delivered and logged only in the browser as required.
5. Remove all server-side `console.log` calls for simulated recovery delivery, password replacement, and privacy acceptance; return non-sensitive mock event indicators in API responses and log those events from the browser client only.

## DECISION

**FAIL**