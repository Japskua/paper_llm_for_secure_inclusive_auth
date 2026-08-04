## SUMMARY

The artifact is a single-file Bun SPA with a largely well-structured recovery flow, TLS configuration, CSRF protection, CSP nonces, password hashing, generic error messages, browser-side mock logging, and working hash-based navigation. However, it has critical authentication and password-reset authorization flaws: any valid-looking identifier can initiate a reset for the fixed internal account and any identifier can be used to log in if the password is known. Token/session expiry is also not enforced server-side after verification, and rate limits can be bypassed by creating new sessions. Therefore, it does not meet the security requirements.

## FUNCTIONAL_CHECK

- **Single `app.ts` artifact containing Bun server, HTML, CSS, and vanilla browser JavaScript — PASS**
  - The provided implementation is one file and uses Bun directly, with no framework, bundler, compilation step, or external assets.

- **TLS server uses supplied local certificates — PASS**
  - `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`.
  - The request handler rejects non-HTTPS URLs.

- **CSRF prevention with unique per-session tokens on sensitive requests — PASS**
  - New sessions receive a cryptographically random CSRF token.
  - All `/api/*` POST endpoints require a matching `X-CSRF-Token`.
  - The session cookie is `Secure`, `HttpOnly`, `SameSite=Strict`, and uses the `__Host-` prefix correctly.

- **Sensitive actions enforce server-side session authorization / avoid IDOR — FAIL**
  - The reset request endpoint accepts any syntactically valid identifier but always creates a reset token for `"internal-demo-account"`.
  - A visitor can submit any arbitrary valid identifier, receive the displayed mock reset token, verify it, and reset the internal account’s password.
  - The login endpoint likewise ignores the supplied identifier and checks the supplied password against the fixed internal account.

- **Password-reset tokens are random, single-use, session-bound, and short-lived — FAIL**
  - Tokens are random, session-bound, and marked used after verification.
  - However, `/api/recovery/reset-password` does not verify `Date.now() <= session.reset.expiresAt`.
  - Once a token is verified before its ten-minute expiry, `session.recoveryVerified` permits password reset indefinitely while the server-side session remains in memory.
  - Server-side sessions themselves do not expire; cookie expiration alone is not server-side session expiration and can be bypassed by manually replaying a copied cookie.

- **Passwords use bcrypt and a strong password policy — PASS**
  - Passwords are hashed and verified using Bun’s bcrypt implementation.
  - The reset policy requires 12–128 characters, uppercase, lowercase, numeric, and symbol characters.

- **MFA is implemented in the recovery/login flow — PASS**
  - Successful password reset and sign-in both require a subsequent MFA verification step.
  - The deterministic mock MFA code is surfaced through the browser Logs panel and `console.log`, as required for the demo.

- **Brute-force / automated guessing attempts are throttled or blocked — FAIL**
  - Rate limits are stored only in the session object.
  - An attacker can create a new session by visiting `/` without the session cookie and receive a fresh attempt budget, bypassing login, recovery request, reset-code, and MFA throttles.
  - Login throttling is especially ineffective because the login route checks a single account but has no shared per-account or per-client limit.

- **XSS/injection protections and safe output handling — PASS**
  - User-provided values are not inserted into HTML.
  - UI status messages are assigned with `textContent`.
  - Static templates use controlled `innerHTML`; no user input is interpolated into those templates.
  - The CSP uses a per-response nonce and disallows externally sourced scripts.

- **Secure headers and production-safe errors — PASS**
  - HSTS, CSP, frame protections, `nosniff`, restrictive referrer policy, permissions policy, and no-store cache headers are configured.
  - Exception handling returns generic errors rather than stack traces or debug information.

- **No disclosure of patient/account identifiers in normal UI — PASS**
  - The UI does not render account IDs, usernames, patient records, or folder-like identifiers.
  - Generic account-recovery messaging avoids account enumeration.

- **Safe-authentication and anti-phishing guidance — PASS**
  - The UI tells users not to share passwords or verification codes and directs them to use the local portal only.

- **Mock recovery/MFA delivery is available in the browser console and UI — PASS**
  - Recovery and MFA test values are logged through browser-side `console.log` and shown in the Logs panel.
  - Manual recovery-code submission is supported.

- **Internal navigation and confirmation access behavior — FAIL**
  - Direct navigation to `#confirmation` displays “Your acknowledgement has been recorded” without checking whether the user is authenticated or has accepted the conditions.
  - Direct navigation to `#privacy` displays the privacy screen even when unauthenticated. The acceptance API is protected, but the SPA’s visible protected-state messaging is not guarded.
  - The confirmation view should be conditioned on authenticated session state and successful privacy acceptance.

- **CSP-compatible styling — FAIL**
  - The Logs `<section>` uses an inline `style="margin-top:1rem"` attribute.
  - The CSP permits styles only with the generated nonce (`style-src 'nonce-...'`) and does not permit inline style attributes.
  - Browsers will block that inline style, causing a CSP violation and leaving the intended margin unapplied.

## FAILING_ITEMS

- The recovery endpoint maps every valid-looking recovery identifier to the same fixed account:
  - `accountId: "internal-demo-account"` is assigned regardless of `data.identifier`.
  - This permits an unauthorized password reset by anyone who can open the site.

- The login endpoint does not authenticate the identifier:
  - It validates only the identifier’s format and then verifies the password against `"internal-demo-account"`.
  - A user can sign in using any valid identifier combined with the internal account’s password.

- Reset-token expiry is not enforced when changing the password:
  - `/api/recovery/reset-password` checks `recoveryVerified` but not `session.reset.expiresAt`.

- Sessions have no server-side expiry:
  - `createdAt` is recorded but never evaluated.
  - The in-memory session remains valid after cookie `Max-Age` unless the server restarts.

- Rate limiting is session-only and bypassable:
  - An attacker can obtain unlimited new sessions and fresh rate-limit histories.

- The confirmation route provides an unauthenticated success claim:
  - `#confirmation` can be opened directly and states that acknowledgement was recorded without server-confirmed state.

- The inline `style` attribute on the Logs card is blocked by the configured CSP.

## NEW_TASKS

1. Bind recovery requests to an actual server-side account lookup and ensure that a reset token is created only for the account associated with the supplied identifier; retain generic responses to avoid account enumeration and keep test-token disclosure limited to the authorized deterministic demo path.

2. Update `/api/login` to resolve the supplied identifier to an account and verify the password only for that resolved account; reject unmatched identifiers with the existing generic authentication message.

3. Enforce reset-token expiry in `/api/recovery/reset-password`, invalidate recovery authorization after expiry, and reject resets unless the verified reset authorization is still within its permitted lifetime.

4. Add server-side session expiry enforcement using `createdAt`, reject expired sessions on every request, and periodically remove expired session records from the in-memory session map.

5. Replace session-only rate limits with shared server-side limits keyed at minimum by target account/identifier and preferably client address as well; apply them to recovery requests, login attempts, reset-code attempts, and MFA attempts.

6. Add authenticated session-state checks for privacy and confirmation rendering so `#confirmation` is shown only after server-confirmed privacy acceptance, and show an access-required screen or redirect for unauthorized hash views.

7. Move the Logs card’s inline `margin-top` declaration into the nonce-authorized stylesheet, removing the CSP-blocked `style` attribute.

## DECISION

FAIL