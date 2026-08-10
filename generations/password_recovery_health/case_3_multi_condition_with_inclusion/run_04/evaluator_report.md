## SUMMARY

The artifact is a valid single-file Bun HTTPS SPA implementing the requested password-recovery, password-reset, login, MFA, and privacy-acceptance flow. It uses inline vanilla HTML/CSS/JavaScript, browser-side simulated delivery logs, server-side session state, CSRF protection, Argon2id password hashing, throttling, token expiration, secure headers, and TLS certificates from the required paths. No compile/build tooling or external assets are used.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun implementation:** The complete server, HTML template, inline CSS, and inline client-side JavaScript are contained in `app.ts`. It is directly runnable by Bun and does not require a bundler, framework, external package, or compilation step.

- **PASS — HTTPS and supplied certificate usage:** The server requires `certs/cert.pem` and `certs/key.pem`, exits if they are absent, and starts Bun with TLS configured. Session cookies are marked `Secure`.

- **PASS — Password-recovery flow is complete and navigable:** The UI supports recovery start, approved-channel confirmation, simulated delivery, link-based verification, manual code verification, password reset, sign-in, MFA, privacy acceptance, and confirmation. Internal recovery links point to a handled route: `/recovery/verify`.

- **PASS — Manual reset-code entry is supported:** The delivery screen provides “Enter a code manually,” and the verification screen accepts a manually entered recovery token. Recovery links also prefill/route the token correctly.

- **PASS — Simulated deliveries are logged in the browser:** Authorization secrets, reset tokens, recovery links, and MFA codes are returned to the client and passed through browser-side `console.log` via `addLog`. The visible Logs panel provides a testing-friendly mirror of these simulated messages.

- **PASS — ADHD/inclusivity UX requirements:** The flow is step-based, provides visible progress, consistently labels the next step, uses straightforward language, avoids countdown pressure, supports pause/return behavior through server-backed state and browser storage, and exposes help/safety advice at all stages.

- **PASS — CSRF protections:** Every state-changing API endpoint requires a session, a matching per-session CSRF token, and same-origin validation. The CSRF token is generated randomly for each server session.

- **PASS — Access-control and session protections:** Sensitive workflow operations are tied to a server-side session cookie with `HttpOnly`, `Secure`, `SameSite=Strict`, and bounded lifetime. Recovery transitions validate the expected stage and cannot be advanced merely by manipulating client state.

- **PASS — Reset-token security:** Reset tokens are generated with cryptographically secure randomness, stored server-side only as SHA-256 digests, expire after 15 minutes, are invalidated after successful password change, and are protected by attempt limits and temporary lockout.

- **PASS — Brute-force mitigation:** Approved-channel verification, reset-code verification, MFA verification, and login attempts are rate-limited/locked after repeated failures. Login throttling is keyed by a hash of the normalized email.

- **PASS — Password security:** New passwords require at least 12 characters with uppercase, lowercase, number, and symbol requirements, reject spaces, and are stored using Bun Argon2id hashing rather than plaintext.

- **PASS — MFA implementation:** MFA is required after password login. The deterministic mock MFA code is delivered through the browser-side simulated log mechanism, and repeated incorrect attempts exhaust the MFA challenge.

- **PASS — XSS/injection controls:** User-provided values are not inserted using `innerHTML`; client rendering uses DOM creation and text nodes. Server responses do not reflect sensitive inputs. Input formats and lengths are validated server-side.

- **PASS — CSP and secure headers:** Responses include HSTS, CSP with a per-page nonce, `X-Content-Type-Options`, `X-Frame-Options`, restrictive `Permissions-Policy`, `Referrer-Policy: no-referrer`, and no-store cache directives.

- **PASS — No external network calls or third-party assets:** Client requests are same-origin API calls only. The CSP restricts network connections to `'self'`; no third-party scripts, styles, images, or redirects are used.

- **PASS — Safe-authentication and anti-phishing guidance:** The help screen advises users to sign in only on the Care Portal, never share passwords or recovery codes, and explains that staff should not request passwords.

- **PASS — Error handling and production behavior:** API failures return generic messages rather than stack traces or debug data. The top-level server handler returns a generic service-unavailable response on unexpected errors.

## FAILING_ITEMS

- None identified.

## NEW_TASKS

1. No remediation tasks required.

## DECISION

PASS