## SUMMARY

The artifact is a single-file Bun/TypeScript password-recovery SPA with a functional recovery, token verification, MFA, password reset, login, and privacy-acceptance flow. It uses HTTPS/TLS, CSRF tokens, CSP nonces, generic recovery responses, rate limiting, Argon2id for changed passwords, and browser-side testing logs. However, it does not fully meet the security requirements because it embeds an initial plaintext password in source code, does not enforce server-side session expiration, permits unauthenticated users to render protected confirmation routes, and does not apply MFA/SSO to the normal login flow.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun server and browser UI**
  - The complete server, HTML template, CSS, and client-side JavaScript are contained in `app.ts`.
  - It uses Bun directly and does not depend on frameworks, bundlers, compilers, or external assets/network calls.

- **PASS — TLS and HTTP-to-HTTPS enforcement**
  - The HTTPS server uses `certs/cert.pem` and `certs/key.pem`.
  - The HTTP listener only issues a `308` redirect to `https://localhost:3000`.

- **PASS — Recovery flow is functional**
  - Users can submit an email address or international phone number.
  - Valid and invalid contact submissions receive the same generic privacy-preserving confirmation response.
  - A simulated reset token is returned only for academic testing and is logged in the browser console/UI logs.

- **PASS — Reset links and manual token submission work**
  - The token may be supplied through `/reset?token=...`.
  - The same token can also be entered manually in the recovery-token form.
  - The token is random, stored as a SHA-256 verifier, short-lived, and marked as single-use after password change.

- **PASS — MFA verification is included in the reset flow**
  - A second factor is required after token verification and before a password may be changed.
  - The deterministic academic MFA code is only surfaced through the browser-side testing log.
  - MFA attempts are throttled.

- **PASS — Strong password policy and password hashing for resets**
  - The server enforces a 14–128-character password policy requiring upper-case, lower-case, number, and symbol characters.
  - New passwords are stored using Bun Argon2id hashing.
  - Password confirmation is verified server-side.

- **FAIL — Passwords are not exclusively stored as hashes**
  - The initial password is present in plaintext in application source:
    ```ts
    let passwordHash = await Bun.password.hash("Welcome!Reset2025", {
    ```
  - Even though it is hashed at startup, the plaintext secret is still stored in the source artifact, violating the requirement that passwords must never be stored in plaintext.

- **PASS — CSRF protections are implemented for state-changing API requests**
  - A random per-session CSRF token is generated.
  - Every API request is POST-only and requires the matching `X-CSRF-Token`.
  - The session cookie is `Secure`, `HttpOnly`, `SameSite=Strict`, and has the correct `__Host-` cookie constraints.

- **FAIL — Sessions do not have server-side expiration**
  - The cookie has `Max-Age=1800`, but session records in the `sessions` map have no expiration value and are never removed or rejected after 30 minutes.
  - A retained/stolen session cookie remains valid server-side indefinitely, including its CSRF token and authenticated status.
  - This does not adequately protect user sessions as required.

- **PASS — Injection/XSS controls are generally strong**
  - User-controlled content is rendered using `textContent` and DOM APIs rather than `innerHTML`.
  - The CSP allows scripts and styles only with a per-page nonce.
  - Inputs are tightly validated server-side, and no untrusted script URLs are introduced.

- **PASS — Security headers and production error behavior**
  - HSTS, CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, and `Cache-Control: no-store` are configured.
  - Error handling returns generic responses without stack traces or debug output.

- **PASS — Brute-force throttling is present**
  - Recovery, token verification, MFA, and login attempts are rate-limited on a per-session/action basis.
  - The reset token is high entropy and has a ten-minute lifetime.

- **FAIL — Protected SPA routes are not access-controlled before rendering**
  - Any visitor can directly navigate to `/privacy` and view the privacy acknowledgement screen without being authenticated.
  - Any visitor can directly navigate to `/confirmed` and see “Your acknowledgement has been securely recorded,” even if no acknowledgement was submitted.
  - While `/api/privacy` correctly enforces authentication, the UI routes themselves present unauthorized success/protected states and therefore do not function correctly as protected routes.

- **FAIL — MFA/SSO is not enforced for normal account login**
  - The recovery/reset path uses MFA, but `/api/login` authenticates solely with the password.
  - A user who knows the password can access the privacy workflow without MFA or SSO.
  - This does not satisfy the requirement that MFA or SSO be implemented for authentication, rather than only during password recovery.

- **PASS — Safe-authentication / anti-phishing guidance is shown**
  - Each relevant screen informs users not to share passwords, recovery tokens, or MFA codes with staff, support, or email messages.
  - The application does not make outgoing URL requests or use user-controlled redirects.

## FAILING_ITEMS

- The initial account password, `Welcome!Reset2025`, is hard-coded in plaintext in `app.ts`.
- Session records have no server-side expiry or cleanup. Cookie expiration alone does not invalidate a session if its cookie is retained or replayed.
- `/privacy` and `/confirmed` render sensitive/protected workflow screens without verifying server-side authenticated or privacy-accepted state.
- The normal password login endpoint does not require MFA or SSO; MFA is limited to the password-reset sequence.
- The CSS declaration `box-shadow:0 2px 8px #1232 2;` is malformed and will be ignored by browsers. This is cosmetic but should be corrected.

## NEW_TASKS

1. Replace the hard-coded plaintext initial password with a precomputed Argon2id hash or a securely supplied runtime secret; do not retain any plaintext password in `app.ts`.
2. Add a server-side session expiration timestamp to `Session`; reject and delete expired sessions in `sessionFor`, and issue a replacement session cookie when needed.
3. Add a read-only authenticated session-status API endpoint, protected by the existing session/CSRF model as appropriate, and use it to prevent unauthenticated rendering of `/privacy`.
4. Prevent rendering of `/confirmed` unless the current server-side session has `privacyAccepted === true`; otherwise route the user to the appropriate recovery/login screen.
5. Implement MFA or SSO for normal `/api/login` authentication, not only for the reset process.
6. Correct the invalid CSS `box-shadow` declaration, for example: `box-shadow: 0 2px 8px #1232;`.

## DECISION

FAIL