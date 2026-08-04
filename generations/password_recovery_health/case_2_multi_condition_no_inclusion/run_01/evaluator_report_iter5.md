## SUMMARY

The artifact is a well-structured single-file Bun SPA with TLS, secure cookies, CSP, session-bound CSRF protection, route-level authorization, bcrypt password updates, throttling, MFA simulation, safe DOM handling, and a functioning recovery-to-privacy flow. However, it does not fully meet the security requirements because the simulated recovery endpoint exposes a valid reset token for the shared evaluation account to any unauthenticated requester who knows or guesses its identifier. Additionally, the preloaded account accepts the known weak password represented by the standard bcrypt fixture hash, undermining the stated strong-password policy.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application / no framework or build tooling**
  - The server, HTML template, CSS, and browser JavaScript are all contained in `app.ts`.
  - It uses `Bun.serve` directly and serves the client script from `/app.js` without bundlers, external packages, or external network calls.

- **PASS — HTTPS and TLS certificate configuration**
  - The Bun server is configured with `certs/cert.pem` and `certs/key.pem`.
  - Requests whose parsed protocol is not `https:` are rejected.
  - Cookies use `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, and a `__Host-` prefix.

- **PASS — Security headers and production-safe error handling**
  - HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, COOP, and no-cache headers are supplied.
  - Errors use generic messages and do not expose stack traces or implementation details.
  - CSP restricts scripts to same-origin resources and styles to nonce-authorized inline CSS.

- **PASS — CSRF protection**
  - A random CSRF token is generated per session.
  - State-changing API routes require a matching `X-CSRF-Token`.
  - Session cookies are `SameSite=Strict`, providing additional CSRF protection.

- **PASS — Session-bound authorization and protected privacy flow**
  - Password reset authorization is session-bound and expires.
  - Privacy acceptance requires a session-authenticated account.
  - The confirmation page is gated by authenticated state and privacy acceptance state.
  - Direct navigation to sensitive SPA views does not grant access because the server endpoints enforce the authorization checks.

- **PASS — Password reset token security mechanics**
  - Recovery tokens are generated using cryptographically secure random bytes.
  - Tokens expire after ten minutes.
  - Tokens are single-use after successful verification.
  - Reset authorization is additionally bound to the issuing session and is cleared after use.

- **PASS — Manual recovery-code entry and recovery-link flow**
  - The recovery UI supports manual code entry.
  - The generated simulated recovery link routes correctly to `/?code=...#verify`.
  - The verification view safely pre-fills the code using an input `.value` assignment, not HTML injection.

- **PASS — XSS/injection handling**
  - User inputs are validated server-side and not reflected in API responses.
  - Browser-side user-derived values are inserted using `textContent` or input `.value`.
  - The dynamic `innerHTML` templates are static literals rather than interpolation of user-controlled data.
  - Query-string token data is not injected into HTML.

- **PASS — Password policy for password reset**
  - New passwords must be 12–128 characters and include uppercase, lowercase, numeric, and symbol characters.
  - Passwords with whitespace are rejected.
  - Reset passwords are hashed using `Bun.password.hash(..., { algorithm: "bcrypt" })`.

- **PASS — Login/recovery/MFA throttling**
  - Recovery request, recovery verification, password reset, login, and MFA verification endpoints have rate-limit checks.
  - Limits are tracked across sessions using client address plus identifier/account keys.
  - MFA is required before privacy acceptance.

- **PASS — Anti-phishing guidance and no exposed patient data**
  - The UI prominently advises users never to share passwords or verification codes.
  - The portal does not display patient data, account IDs, course folders, or usernames.
  - The privacy and confirmation screens avoid displaying account/patient identifiers.

- **FAIL — Password recovery must prevent unauthorized account reset**
  - `POST /api/recovery/request` returns a real, usable `testCode` and `resetPath` whenever the submitted identifier resolves to `evaluation.mock@hospital.test`.
  - The requester does not need access to an independent registered recovery channel, existing authentication, or another recovery factor.
  - Any party who knows or guesses that identifier can create their own session, receive a valid reset code, verify it, choose a new password, and complete MFA for the shared evaluation account.
  - Session binding does not solve this issue because the attacker receives the token in their own session.

- **FAIL — Recovery response is not actually anti-enumeration-safe**
  - The textual `message` is generic, but the response body differs for the registered evaluation account because it includes `testCode` and `resetPath`.
  - An attacker can distinguish the one eligible account from invalid or unknown identifiers by inspecting the API response or observing whether the simulated recovery link appears.
  - This conflicts with the UI statement that the response is identical whether an account exists, is eligible, or is invalid.

- **FAIL — Strong password policy is not enforced for the pre-existing login credential**
  - The initial password hash is the well-known bcrypt fixture hash:
    - `$2b$12$C6UzMDM.H6dfI/f/IKcEe.7E4ffBMOAxfB6CZzK4SWFg4T49Xlv4S`
  - This standard fixture corresponds to the weak password `password`.
  - The `/api/login` endpoint accepts that password without applying the password policy, so the supplied account begins with a password that violates the stated 12-character, mixed-character policy.
  - The source comment claiming that the corresponding credential is intentionally absent is misleading because this commonly known fixture is readily identifiable.

- **PASS — Browser console delivery logging**
  - Simulated reset delivery and MFA delivery are logged in the browser through `console.log`.
  - Reset and MFA test values are also made visible in the Logs panel for the evaluation flow.

## FAILING_ITEMS

- The recovery-request endpoint lets an unauthenticated requester obtain a valid password-reset token for the shared evaluation account solely by submitting its identifier.
- The recovery API leaks account eligibility/existence through the presence of `testCode` and `resetPath`, despite returning a generic message.
- The initial evaluation account uses a known weak password (`password`) through a public bcrypt fixture hash, violating the strong-password-policy requirement.
- The comment stating that the initial credential is not present in source code is inaccurate and should not be relied on as a security control.

## NEW_TASKS

1. Replace the shared pre-existing evaluation account recovery model with a recovery simulation that cannot reset another user’s account merely from knowledge of an identifier; use a disposable session-scoped mock account/challenge or require a separately verified recovery factor before issuing a usable reset token.

2. Make `/api/recovery/request` response structure indistinguishable for valid, invalid, and unknown identifiers; do not conditionally expose `testCode` or `resetPath` based on account existence or eligibility.

3. Preserve evaluator usability by logging/showing a simulated recovery code only for a non-shared, session-scoped mock recovery flow that cannot affect any persistent or other-session account.

4. Remove the known bcrypt fixture hash and initialize the evaluation account with a password that satisfies the stated password policy, or require an initial secure password setup flow before login is permitted.

5. Update the source comments around the evaluation credential so they accurately describe the credential lifecycle and do not claim that a recoverable/publicly known password is absent.

## DECISION

**FAIL**