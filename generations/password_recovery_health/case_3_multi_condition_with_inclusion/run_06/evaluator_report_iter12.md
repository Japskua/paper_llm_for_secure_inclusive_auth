## SUMMARY

The artifact is a single `app.ts` Bun application with a functional vanilla HTML/CSS/JS password recovery flow, HTTPS redirect, session cookies, CSRF protection, password reset/MFA steps, browser-console mock delivery values, and accessible progress/help UI. Most functional and security requirements are implemented correctly. However, it does not fully meet the strong-password/security-throttling requirements: the bundled initial password hash corresponds to a weak, publicly known password, and the global throttling mechanism allows one attacker to lock out all users from an action.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no build tooling or external assets.**  
  Server, HTML, CSS, and client JavaScript are all contained in `app.ts`. The JavaScript is served from the in-memory `/app.js` route, not from an external file or build output.

- **PASS — Bun serves the SPA directly over TLS and redirects HTTP to HTTPS.**  
  The HTTPS Bun server uses `certs/cert.pem` and `certs/key.pem`; the HTTP listener responds with a `308` redirect to `https://localhost:3443`.

- **PASS — Password recovery flow is functional and structured.**  
  The flow supports requesting a reset, verifying a recovery token manually or via the simulated-link button, sending/verifying MFA, setting a new password, then signing in and accepting privacy conditions.

- **PASS — Recovery delivery and MFA simulations are usable and logged in the browser.**  
  The reset token and mock MFA codes are returned only to the session-bound UI status endpoints and are logged through browser-side `console.log`. The UI includes a Logs panel and supports manual token/code entry.

- **PASS — Progress, orientation, help, and pause/return support are implemented.**  
  The recovery UI has five visible progress steps, an orientation reminder, no visible countdown, a persistent server-side recovery state per session, and a globally available help/safe-sign-in section.

- **PASS — CSRF protection is implemented for state-changing API requests.**  
  A cryptographically random CSRF token is generated per server-side session and checked by `guarded()` on all sensitive POST routes, including recovery request, token/MFA verification, password change, login, privacy acceptance, and logout.

- **PASS — Session security and access control are generally sound.**  
  The session cookie is `HttpOnly`, `Secure`, `SameSite=Strict`, and uses a random token. Privacy acceptance requires an authenticated account in the active session. Recovery records are session-bound and cannot target arbitrary account identifiers.

- **PASS — XSS protections are adequate for this vanilla implementation.**  
  User-controlled values are not inserted using `innerHTML`; UI log/status output uses `textContent`. The CSP disallows inline scripts and only allows scripts from `'self'`. No external resources are loaded.

- **PASS — Secure response headers and caching controls are present.**  
  The application sets HSTS, CSP, clickjacking protections, MIME sniffing protection, referrer policy, permissions policy, and no-store cache headers.

- **PASS — Reset tokens are cryptographically random, session-bound, short-lived, and single-use.**  
  Reset tokens are generated with `randomBytes`, expire after 15 minutes, are validated against the current session’s reset record, and are invalidated after password change.

- **PASS — Password changes are hashed with bcrypt and a password policy is enforced for new passwords.**  
  New passwords require 12–128 characters, uppercase, lowercase, a number, and a non-whitespace symbol. They are stored using `Bun.password.hash(..., { algorithm: "bcrypt", cost: 10 })`.

- **PASS — MFA is implemented for recovery and sign-in.**  
  Password recovery requires recovery-token verification plus MFA verification before a password can change. Standard sign-in also requires an additional MFA step before authentication is established.

- **FAIL — The initial sign-in credential does not satisfy the strong-password requirement.**  
  The fixed bcrypt hash (`$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy`) is the widely known bcrypt test hash for the weak password `password`. The login endpoint permits this weak password even though the requirements state that authentication requires a strong password and that a strong password policy must be enforced.

- **FAIL — The global throttling design permits cross-user denial of service.**  
  `globalAttempts` is keyed only by action name, such as `global:login` and `global:reset-verify`, not by account, session, IP, or another requester scope. Twenty failures distributed across sessions can lock the global action for 15 minutes, blocking legitimate users. This is not a safe brute-force mitigation and conflicts with the low-stress/no-unnecessary-lockout experience.

- **PASS — No open redirects, SSRF-capable outgoing requests, or staff impersonation paths are present.**  
  Redirect destinations are server-defined and no outbound network fetches are performed. The help text tells users not to share their password or security code.

## FAILING_ITEMS

- The initial stored bcrypt credential is for a weak and publicly known password (`password`). This permits weak-password authentication before recovery and does not enforce the required strong-password policy consistently.

- Brute-force tracking uses a single process-wide counter per action. An attacker can intentionally generate enough failures to lock out every user from login or recovery-code verification for 15 minutes.

## NEW_TASKS

1. Replace the known weak initial bcrypt hash with a bcrypt hash for a password satisfying the same `validPassword()` policy, and ensure every login-capable account is created or seeded only with policy-compliant passwords.

2. Replace action-wide `globalAttempts` throttling with scoped rate limiting keyed by an appropriate requester identity, such as a privacy-preserving IP-based key plus session/account-specific counters; ensure one requester’s failures cannot lock out unrelated users.

3. Preserve per-session/account login and verification attempt limits while returning a clear, non-revealing retry message when that specific requester is temporarily blocked.

## DECISION

FAIL