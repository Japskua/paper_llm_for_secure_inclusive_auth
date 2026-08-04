## SUMMARY

The artifact is a valid single-file Bun HTTPS SPA with a clear, accessible recovery flow, CSRF protection, CSP nonces, session-bound recovery state, Argon2id password hashing, MFA simulation, and working client-side navigation. However, it does not fully meet the security requirements: password-reset and sign-in brute-force controls are only session-scoped and can be bypassed by obtaining a new session, and the reset flow does not establish that the requester controls a specific account contact before permitting a global password change. It also emits several mock events through the server console despite the explicit requirement that mocks use browser `console.log`.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun server, HTML, CSS, and vanilla browser JavaScript**
  - All server logic and the HTML/CSS/client JavaScript are contained in `app.ts`.
  - No frameworks, bundlers, compilation steps, or external assets are used.

- **PASS — HTTPS and HTTP-to-HTTPS redirect**
  - The Bun HTTPS listener uses `certs/cert.pem` and `certs/key.pem`.
  - A separate HTTP listener redirects to the fixed HTTPS localhost origin.
  - The application fails safely at startup if certificates are absent.

- **PASS — Clear, structured, low-distraction recovery UX**
  - The UI has visible numbered progress, one step per screen, straightforward language, accessible focus styles, help guidance, and a pause/resume affordance.
  - It avoids automatic redirects during recovery and provides status messages after actions.

- **PASS — Recovery code can be submitted manually**
  - The recovery token is shown in the simulation log and prefilled into a normal editable input.
  - The user can replace the prefilled value and submit the recovery code manually.

- **PASS — Internal recovery, sign-in, privacy, and appointment navigation works**
  - The routes `/`, `/reset`, `/signin`, `/account`, and `/appointment` are served.
  - The SPA controls route changes with History API and supports browser back/forward handling.
  - Server-side route guards redirect unauthorized direct requests to protected routes.

- **PASS — Session recovery state can be restored**
  - Recovery state is retained server-side in the browser session.
  - `/api/recovery/state` restores a valid pending reset token and stage after a refresh or return to `/reset`.

- **PASS — CSRF controls are present on sensitive API requests**
  - A cryptographically random CSRF token is generated per server session.
  - API requests require that token before reset, sign-in, MFA, privacy acceptance, or appointment actions are processed.
  - Session cookies are `Secure`, `HttpOnly`, `SameSite=Strict`, and correctly use the `__Host-` cookie prefix requirements.

- **PASS — XSS protections are substantially implemented**
  - Request values are not interpolated into HTML.
  - Client-rendered user-facing values use `textContent`, not `innerHTML`.
  - CSP restricts the page to nonce-authorized static inline style/script blocks and blocks external script sources.
  - No external or user-controlled scripts are loaded.

- **PASS — Secure headers and HTTPS configuration**
  - CSP, HSTS, `X-Content-Type-Options`, frame restrictions, referrer policy, permissions policy, COOP, CORP, and no-store caching headers are configured.
  - HTTP requests are redirected to HTTPS.
  - Error responses are generic and do not disclose stack traces.

- **PASS — Random, expiring, session-bound reset tokens**
  - Reset tokens are generated with cryptographically secure randomness.
  - They expire after 10 minutes.
  - They are session-bound and invalidated after a successful password update.
  - Token comparisons use timing-safe equality.

- **FAIL — Password reset flow does not adequately prevent unauthorized password changes**
  - Any visitor can submit any syntactically valid email address to `/api/reset/request`.
  - The API then returns a usable reset token to that same unauthenticated session.
  - That token can reset the shared global `storedPasswordHash`, regardless of whether the visitor controls the email/account being “recovered.”
  - This means a new session can reset the application password without proving ownership of a known account contact. The simulation requirement to expose a test token can still be met, but it must be tied to a deterministic mock account/contact and modeled as delivery only to that account’s simulated channel.

- **FAIL — Sign-in brute-force protection is bypassable**
  - Login failures and lockout state are stored only in the current browser session.
  - An attacker can clear cookies, use private browsing, or create a new session to immediately obtain five more password attempts.
  - There is no account-level or source-level throttle, CAPTCHA, or durable lockout mechanism.

- **FAIL — Recovery request throttling is bypassable**
  - Reset request limiting is also stored only in `session.reset`.
  - A new session bypasses the three-request limit immediately.
  - The requirement calls for protection against automated guessing/abuse; per-session-only limits are insufficient.

- **PASS — MFA exists and has attempt/expiry controls**
  - A cryptographically random six-digit MFA code is generated after successful password verification.
  - MFA codes expire after 10 minutes.
  - MFA attempts are limited and lock for 15 minutes after repeated failures.
  - MFA verification is required before privacy acceptance and appointment request actions.

- **PASS — Password policy and password hashing**
  - Passwords must be 12–128 characters and include uppercase, lowercase, numeric, and symbol characters, with no spaces.
  - Passwords are stored only as Argon2id hashes via `Bun.password.hash`.
  - Password verification uses `Bun.password.verify`.

- **PASS — Protected routes avoid direct object references and private-data exposure**
  - The implementation has no user IDs, patient IDs, usernames, course folders, or object identifiers in URLs or APIs.
  - `/api/privacy` and `/api/appointment` require authenticated state, and appointment creation additionally requires privacy acceptance.

- **PASS — Safe-authentication and anti-phishing guidance**
  - The UI tells users not to share passwords or codes by email, phone, or text.
  - It directs users to use the hospital’s normal published contact number if something feels unexpected.
  - Redirect destinations are fixed/whitelisted rather than based on user input.

- **FAIL — Mock logging does not comply fully with the browser-console-only requirement**
  - The requirements specify: “All mocks via `console.log` IN THE BROWSER.”
  - The code logs several mock events from the Bun server:
    - `[mock delivery] Password recovery code prepared...`
    - `[mock verification] Password replacement completed...`
    - `[mock MFA] ...`
    - `[mock privacy] ...`
    - `[mock appointment] ...`
  - Only some test values are also logged in the browser. All mock simulation events must be emitted via browser `console.log`, not server-side logs.

- **PASS — No external network calls**
  - Browser requests are same-origin API calls only.
  - The application does not call third-party services or load external resources.

- **PASS — Basic source validity**
  - The TypeScript/Bun APIs and syntax are internally coherent for Bun 1.3.0 usage.
  - The server startup, request routing, header construction, session handling, and client rendering logic do not contain an obvious compile-blocking error.

## FAILING_ITEMS

- The password reset endpoint grants a reset token to any unauthenticated session supplying any email-shaped string, without validating that the request corresponds to a specific allowed mock account or that the requester is entitled to reset that account.
- `storedPasswordHash` is global rather than tied to an account record, so any successful reset changes the effective password for the entire application.
- Login throttling/lockout is tracked only per session and is trivially bypassed by starting a new session or clearing cookies.
- Reset-request throttling is tracked only per session and is trivially bypassed by starting a new session or clearing cookies.
- Mock-related `console.log` calls remain on the Bun server, contrary to the requirement that all mocks are logged in the browser console.

## NEW_TASKS

1. Replace the global password variable with a deterministic in-memory mock account record containing an allowed account contact, an Argon2id password hash, account-level sign-in failure counters, account-level lockout time, reset-request counters, and reset verification counters.

2. Restrict password-reset initiation to the deterministic mock account contact while retaining account-enumeration-safe UI/API messaging; create a reset record only for that account and session after the simulated contact-delivery condition is satisfied.

3. Make reset tokens reference the intended mock account internally and permit password replacement only when the token is valid, session-bound, unexpired, verified, and bound to that account.

4. Move sign-in rate limiting and lockout tracking from session-only state to the mock account record, so a new browser session cannot bypass the five-attempt lockout.

5. Move password-reset request and verification throttling from session-only state to the mock account record, optionally adding a bounded source/session throttle as a secondary control.

6. Remove server-side mock `console.log` calls and return non-sensitive simulation event data to the SPA so the browser client performs every required mock `console.log` itself.

## DECISION

**FAIL**