## SUMMARY

The artifact is a single-file Bun/vanilla-JavaScript password-recovery SPA with TLS, session cookies, CSRF protections, CSP nonces, input allowlists, token hashing, Argon2id password hashing, rate limits, simulated browser-console delivery, and a manual recovery-code entry screen. Most security and functional requirements are addressed. However, the provided internal “Start over” / “Begin another recovery session” links do not work because routing refuses to leave the server-recorded stage, and the password hash is committed before MFA succeeds, meaning MFA does not protect the password-reset action itself.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun server plus HTML, CSS, and vanilla browser JavaScript**
  - All server logic and the generated SPA are contained in `app.ts`.
  - No frameworks, build tools, external assets, external requests, or client compilation are used.

- **PASS — TLS/HTTPS is configured and used**
  - `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`.
  - Requests whose URL protocol is not HTTPS are rejected.
  - Cookies use the `Secure` attribute.

- **PASS — Security headers and CSP are configured for the HTML application**
  - The HTML response includes HSTS, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, cache prevention, and a nonce-based CSP.
  - The CSP limits scripts and styles to server-generated nonce-bearing elements and does not allow arbitrary inline event handlers or external scripts.

- **PASS — CSRF protection is implemented for state-changing API requests**
  - POST requests require a same-origin HTTPS `Origin`.
  - Both an `X-CSRF-Token` header and a JSON-body `csrf` field must match the session CSRF token.
  - CSRF values are generated per session with cryptographically secure randomness.

- **PASS — Session and sensitive-flow access control are present**
  - Recoveries are tied to the owning session through `sessionId` and `session.recoveryId`.
  - A session cannot use another recovery record merely by knowing an identifier.
  - State progression is validated server-side before token verification, password setting, MFA verification, and completion.

- **PASS — XSS/injection resistance is generally implemented**
  - User input is not reflected into HTML responses.
  - Client rendering uses `textContent` and DOM construction rather than HTML-string interpolation of user-controlled data.
  - Contact, token, and MFA inputs use narrow server-side allowlists.
  - No untrusted scripts are loaded.

- **PASS — Reset tokens are random, hashed, single-use, and short-lived**
  - Tokens are generated from 32 random bytes.
  - Only a SHA-256 hash is retained server-side.
  - Tokens expire after 10 minutes and are marked used after successful verification.
  - Token verification attempts are rate-limited.

- **PASS — Password policy and password hashing are implemented**
  - Passwords require at least 14 characters, uppercase, lowercase, number, symbol, and no spaces.
  - Passwords are hashed with Bun Argon2id support and are not logged or stored as plaintext in recovery state.

- **PASS — Brute-force controls are implemented on verification, password, and MFA attempts**
  - Token verification, password submission, and MFA verification each have attempt counters and temporary lockouts.
  - Limits are checked server-side.

- **PASS — Simulated delivery is shown in the browser console and manual code entry works**
  - The reset token and deterministic MFA code are emitted with browser `console.log`.
  - The token is manually submittable through the recovery-code form.
  - No external delivery service is called.

- **PASS — Safe-authentication guidance is present**
  - The UI warns users not to disclose passwords or recovery codes to callers, email senders, or supposed hospital staff.

- **FAIL — All internal links function correctly**
  - `startOverLink()` creates `href="#request"` links, and the completion screen creates a `#request` link.
  - However, `route()` only permits navigation when `requested === serverStage`.
  - During verification, password, MFA, or completion, `serverStage` is not `"request"`, so clicking either “Start over” or “Begin another recovery session” immediately renders the current stage again instead of starting over.
  - This violates the requirement that internal links function correctly.

- **FAIL — MFA does not protect the actual password-reset commit**
  - `/api/set-password` immediately writes `recovery.passwordHash` and sets `passwordSet = true` before MFA succeeds.
  - MFA is only checked afterward in `/api/verify-mfa`.
  - Therefore, a party able to reach the password-setting step can alter the password before completing the intended MFA security check.
  - The password hash must remain pending until successful MFA verification, then be committed as the completed password reset.

## FAILING_ITEMS

- The “Start over” links on the verification screen and the “Begin another recovery session” link on the completion screen are nonfunctional due to the `route()` stage-equality restriction.
- Password reset state is committed before MFA verification. `recovery.passwordHash` is assigned in `/api/set-password`, so MFA is not an effective gate for the sensitive password-reset action.

## NEW_TASKS

1. Add a CSRF-protected `POST /api/recovery-reset` endpoint that clears the current session’s `recoveryId` (and preferably rotates the session CSRF token), then update both “Start over” links to call it, set `serverStage` to `"request"`, and navigate to `#request`.
2. Change the recovery model to store a `pendingPasswordHash` after `/api/set-password`; only move it to the final password-hash field and mark the recovery completed after `/api/verify-mfa` succeeds. Ensure failed, expired, or locked MFA attempts cannot finalize or activate the pending password change.

## DECISION

**FAIL**