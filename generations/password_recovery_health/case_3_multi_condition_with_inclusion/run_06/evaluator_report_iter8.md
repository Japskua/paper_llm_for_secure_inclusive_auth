## SUMMARY

The artifact is a single-file Bun application with a functional HTTPS SPA recovery flow, CSRF protection, secure cookies, CSP/security headers, token expiry/single-use controls, throttling, browser-side mock delivery logs, and accessible step-by-step UX. However, it fails the authentication security requirements because the seeded account uses a publicly known bcrypt hash for the weak password `password`, allowing direct sign-in without completing recovery or using a strong password.

## FUNCTIONAL_CHECK

- **Single-file `app.ts` Bun server and browser UI with no bundler/framework/external assets — PASS**
  - The HTML, CSS, browser JavaScript, API handling, and Bun TLS servers are all contained in `app.ts`.
  - `/app.js` is generated and served from the same file. No external assets or network calls are used.

- **HTTPS enforcement and use of provided TLS certificates — PASS**
  - The HTTPS server uses `certs/cert.pem` and `certs/key.pem`.
  - The HTTP server redirects requests to `https://localhost:3443` with HTTP 308.
  - HSTS is sent by HTTPS responses.

- **Clear, low-stress, inclusive multi-step recovery UX — PASS**
  - The UI presents five visible recovery steps, an orientation message, no countdown, persistent server-side recovery state, clear status messages, and accessible help.
  - Recovery expiration returns the user safely to step 1 with an explanation.
  - The flow supports both simulated-link autofill and manual token entry.

- **Recovery request, token verification, MFA verification, password update, login, and privacy acceptance flow — PASS**
  - The intended workflow is functional: request recovery, obtain the logged mock token, verify it, obtain and verify MFA code, set a compliant password, sign in, and accept privacy conditions.
  - Internal routes `/recovery`, `/login`, and `/privacy` are handled by the SPA and server.

- **CSRF protection and sensitive-route access control — PASS**
  - Sensitive POST endpoints require a session and validate a session-specific `X-CSRF-Token`.
  - Session cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - Password changes require a valid, verified, unused reset token and verified MFA.
  - Privacy acceptance requires an authenticated server-side session.

- **XSS/injection protections — PASS**
  - The client uses `textContent` rather than `innerHTML` for dynamic values.
  - User input is not reflected into HTML.
  - The CSP restricts scripts to same-origin `/app.js`; no inline JavaScript is used.
  - API responses do not disclose account identifiers or reflect submitted contact details.

- **Reset-token security — PASS**
  - Reset tokens are generated with cryptographically secure random bytes.
  - Tokens are bound to the session/account, expire after 15 minutes, are single-use, and are invalidated when a replacement is requested.
  - The token is only displayed through the required deterministic testing simulation in the browser log/UI.

- **Throttling / brute-force protections — PASS**
  - Login, reset-token verification, MFA verification, and delivery issuance have session and global throttling/lock behavior.
  - Failure responses are generic and do not reveal whether an account exists.

- **Password hashing and strong password policy — FAIL**
  - Newly set passwords are bcrypt-hashed and the new-password policy is strong.
  - However, the initial account password hash is the well-known bcrypt test hash for the weak password `password`:
    ```ts
    "$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
    ```
  - An attacker can directly submit `password` to `/api/login` and authenticate, bypassing recovery and violating the requirement that a strong password policy be enforced and that unauthorized access be prevented.

- **Mock delivery values logged in the browser — PASS**
  - The reset token and MFA code are returned only in simulation mode and are logged in the browser through the `log()` function, as required for testing.
  - No actual email/SMS/network delivery occurs.

## FAILING_ITEMS

- The demo account is initialized with a publicly known weak password hash for `password`. This directly violates the strong password policy and permits unauthorized authentication through the fixed login endpoint.
- Because the account can be signed into with `password`, the intended secure recovery/MFA process is not required to access the authenticated privacy-acceptance route.

## NEW_TASKS

1. Replace the seeded `demoAccount.passwordHash` with a bcrypt hash of a strong, non-public demonstration password that satisfies the same 12-character uppercase/lowercase/number/symbol policy enforced by `validPassword`.
2. Ensure the chosen initial demonstration password is not included in the source code, browser UI, browser logs, API responses, or server logs.
3. Verify that `/api/login` rejects `password` and only accepts the strong seeded password or a password set through the completed reset flow.

## DECISION

**FAIL**