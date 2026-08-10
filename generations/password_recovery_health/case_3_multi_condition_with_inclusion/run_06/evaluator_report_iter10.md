## SUMMARY

The artifact is a well-structured single-file Bun application with a functional recovery, MFA, password reset, sign-in, and privacy-acceptance flow. It uses HTTPS/TLS, session-bound CSRF tokens, CSP/security headers, browser-side safe DOM updates, rate limiting, bcrypt hashing for changed passwords, and simulated browser-console delivery values. However, the preconfigured account hash is the well-known bcrypt hash for the weak password `password`, so the currently usable sign-in credential violates the stated strong-password policy. Therefore, the artifact cannot be accepted as fully compliant.

## FUNCTIONAL_CHECK

- **Single `app.ts` artifact containing Bun server, HTML, CSS, and vanilla browser JavaScript: PASS**
  - The server, HTML template, CSS, and browser script are all contained in `app.ts`.
  - No frameworks, bundlers, external scripts, or external network calls are used.

- **Bun serves the application directly with TLS certificates from `certs/cert.pem` and `certs/key.pem`: PASS**
  - `readFileSync("certs/cert.pem")` and `readFileSync("certs/key.pem")` are used for the TLS Bun server.
  - HTTP on port 3000 redirects to HTTPS on port 3443.

- **Password recovery flow is functional and supports manual code entry: PASS**
  - A recovery request issues a random reset token for the matching simulated account.
  - The token is returned only in simulation mode and is logged by browser JavaScript.
  - The user can either use the simulated “Open recovery link” control or manually paste/type the recovery token.
  - Reset verification, MFA verification, password update, sign-in, and privacy acceptance are connected end-to-end.

- **Recovery flow is clear, structured, and ADHD-friendly: PASS**
  - The five-step progress indicator remains visible.
  - The orientation text tells the user their current step and next action.
  - UI wording is straightforward and avoids unnecessary information.
  - Help/safe-sign-in guidance is visible at all stages.
  - The flow avoids automatic navigation during recovery steps and provides clear status feedback.
  - Recovery progress persists server-side for the session, subject to the required short-lived reset-token expiration.

- **No unintended external navigation, open redirect, or SSRF behavior: PASS**
  - Routes are fixed internal paths only.
  - No user-provided URL is fetched or used as a redirect target.
  - The HTTP redirect is hardcoded to `https://localhost:3443`.

- **CSRF protection for sensitive requests: PASS**
  - A cryptographically random CSRF token is generated per server session.
  - Sensitive POST endpoints use `guarded()` and require the matching `X-CSRF-Token`.
  - Session cookies use `HttpOnly`, `Secure`, and `SameSite=Strict`.

- **Access control and IDOR protection: PASS**
  - The browser never receives account IDs or account records.
  - Reset state is bound to the server-side session and to a server-side account ID.
  - Privacy acceptance requires an authenticated session.
  - Password changes require a valid, verified, MFA-confirmed reset record for the same session.

- **XSS and injection protections: PASS**
  - User-controlled values are not inserted with `innerHTML`.
  - Client-side logs and status messages use `textContent`.
  - The HTML template is static.
  - CSP restricts scripts to same-origin `/app.js` and blocks object embedding and framing.
  - No user input is used in server-rendered HTML, URL construction, or redirects.

- **Security headers and HTTPS enforcement: PASS**
  - HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and no-store cache headers are present.
  - HTTP requests receive a 308 redirect to HTTPS.
  - TLS is configured with the supplied certificate and key files.

- **Reset-token security: PASS**
  - Reset tokens use `randomBytes()` and Base64URL encoding.
  - Tokens are 32 random bytes, not predictable, are session-bound, expire after 15 minutes, and are marked single-use after password change.
  - Replacement recovery requests invalidate the previous token by replacing the server-side reset record.

- **MFA simulation is present and functional: PASS**
  - A recovery token must be verified before MFA can be sent.
  - MFA must be sent before verification succeeds.
  - The deterministic practice MFA code is returned only in simulation mode and logged in the browser console/UI logs.

- **Brute-force mitigation: PASS**
  - Reset-token verification, MFA verification, and login attempts have session and global failure tracking.
  - Repeated failures cause a 15-minute lockout.
  - Recovery and MFA message issuance are also rate-limited.

- **Passwords are stored using bcrypt after password reset: PASS**
  - Password updates use `Bun.password.hash(..., { algorithm: "bcrypt", cost: 10 })`.
  - Plaintext reset passwords are not logged or stored.

- **Strong password policy is fully enforced: FAIL**
  - New passwords are properly validated for length, upper/lowercase, number, symbol, and no whitespace.
  - However, the initial stored hash is `$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy`, the widely known bcrypt example hash for the weak password `password`.
  - The login endpoint accepts this weak password for the active demo account, so the system’s currently usable sign-in credential does not meet the requirement that a strong password policy be enforced.

- **Safe authentication and anti-phishing guidance: PASS**
  - Help text tells users that staff will never ask for their password or security code.
  - The UI advises the user to check the HTTPS localhost address before entering a code.
  - The login experience stays on the fixed hospital-origin application.

## FAILING_ITEMS

- **The active demo account uses a weak initial password.**
  - The configured bcrypt hash is a known hash for `password`.
  - This allows authentication with a weak credential despite the reset-password policy requiring a strong password.
  - It contradicts the requirement that a strong password policy be enforced.

## NEW_TASKS

1. Replace `demoAccount.passwordHash` with a bcrypt hash generated from a password that satisfies `validPassword()`—at least 12 characters, uppercase, lowercase, number, and symbol, with no whitespace.
2. Verify that the replacement initial credential can successfully complete `/api/login` and that a weak credential such as `password` no longer authenticates.

## DECISION

**FAIL**