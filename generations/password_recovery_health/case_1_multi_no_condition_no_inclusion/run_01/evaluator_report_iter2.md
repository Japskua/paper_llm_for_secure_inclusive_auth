## SUMMARY

The artifact is a well-structured single-file Bun/vanilla-JavaScript password-recovery SPA with TLS startup validation, secure cookies, CSP nonces, CSRF protection, session-bound reset tokens, password hashing, MFA simulation, and a functional recovery UI. However, it does not fully meet the brute-force protection requirements: ownership-proof attempts are unlimited, and the shared rate limiter trusts attacker-controlled `X-Forwarded-For` headers, allowing attackers to evade throttling. Therefore, the artifact cannot be accepted as secure against automated guessing attempts.

## FUNCTIONAL_CHECK

- **PASS — Single-file `app.ts` implementation with Bun server, HTML, CSS, and browser JavaScript**
  - The provided artifact contains the Bun server, TLS setup, HTML template, inline nonce-authorized CSS, and vanilla browser JavaScript in one file.
  - No framework, bundler, compiler, or external assets are used.

- **PASS — TLS certificates are required and used for the Bun HTTPS server**
  - The server loads `certs/cert.pem` and `certs/key.pem`.
  - It exits without starting when either certificate is unavailable or empty.
  - An HTTP listener redirects only to the fixed localhost HTTPS origin.

- **PASS — HTTPS/security headers are configured**
  - Responses include HSTS, CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, permissions policy, cross-origin policies, and no-cache headers.
  - CSP uses per-response nonces for the inline style and script blocks.

- **PASS — CSRF protection is session-specific and applied to sensitive POST actions**
  - A random CSRF token is created per session.
  - `/api/request-reset`, `/api/prove-ownership`, `/api/verify-token`, `/api/change-password`, `/api/verify-mfa`, and `/api/accept-privacy` all require a valid session CSRF token.
  - The session cookie is `HttpOnly`, `Secure`, `SameSite=Strict`, path-scoped, and uses the `__Host-` prefix.

- **PASS — Reset tokens are random, short-lived, single-use, and session-bound**
  - Tokens are generated with cryptographically secure random bytes.
  - Tokens expire after ten minutes, are marked used after verification, and are tied to the session that completed ownership proof.
  - Manual code submission and same-browser reset-link verification are both implemented.

- **PASS — Password policy and hashing are implemented**
  - Passwords require 12–128 characters with uppercase, lowercase, numeric, and symbol characters.
  - The new password is hashed with Bun bcrypt support and plaintext is not persisted in server state.

- **PASS — MFA is implemented as a deterministic academic mock**
  - The post-reset MFA step is required before privacy-consent acceptance.
  - The mock MFA value is delivered through the browser-side mock logging flow as required.

- **PASS — UI is functional and follows the required recovery flow**
  - The SPA supports reset request, ownership proof, recovery-code verification, password change, MFA, privacy-condition acceptance, and completion.
  - Browser-side mock events, including recovery delivery details, are written to `console.log` and shown in the visible Logs panel.
  - The reset token is included in the browser-side simulated delivery log.

- **PASS — Private identifiers are not exposed and account enumeration is mitigated**
  - Submitted identifiers are deliberately not stored, compared, or reflected.
  - Reset-request responses have the same response shape and wording for every identifier.

- **PASS — User input is not inserted as HTML**
  - Client rendering uses DOM creation APIs and `textContent`.
  - User-controlled values are not interpolated into HTML templates or used as navigation destinations.
  - The application does not make external network calls or allow open redirects.

- **PASS — Anti-phishing and safe-authentication guidance is visible**
  - Each recovery step presents guidance stating that hospital staff will not request passwords or verification codes through email or phone.
  - Navigation is limited to fixed same-origin routes.

- **FAIL — Automated guessing attempts are not adequately throttled or blocked**
  - `/api/prove-ownership` has no rate limiting at all.
  - An attacker can repeatedly submit ownership-proof guesses without a lockout, delay, CAPTCHA, or rate limit.
  - This violates the requirement that automated guessing attempts be throttled or blocked and weakens the authorization gate before reset-token issuance.

- **FAIL — Existing throttling can be bypassed through untrusted `X-Forwarded-For` values**
  - `throttleScope()` accepts any syntactically matching `X-Forwarded-For` header directly from the request.
  - An attacker can send a different spoofed `X-Forwarded-For` value on every request to receive a fresh throttle bucket.
  - Consequently, reset-token and MFA attempt limits are not reliably enforceable against a direct attacker.

- **PASS — Errors do not expose stack traces or debug data**
  - Unexpected server errors return a generic response.
  - No stack traces, filesystem paths, session IDs, or internal error details are returned to the browser.

## FAILING_ITEMS

- **Ownership proof is vulnerable to unlimited brute-force attempts.**
  - `POST /api/prove-ownership` validates a deterministic proof value but never invokes `isSharedBlocked()` or `registerSharedAttempt()`.
  - Repeated invalid proof submissions are unrestricted.

- **Rate-limit identity can be spoofed.**
  - `throttleScope()` treats `X-Forwarded-For` as authoritative even though the application does not establish that it is behind a trusted reverse proxy which strips client-provided forwarding headers.
  - A malicious client can rotate arbitrary header values and bypass rate limits for token verification and MFA verification.

## NEW_TASKS

1. Add server-side throttling and temporary blocking to `POST /api/prove-ownership`, using a dedicated action key such as `ownership-proof-failure`; check blocking before validation and register failures after invalid proof submissions.

2. Replace untrusted direct use of `X-Forwarded-For` in `throttleScope()` with a trustworthy client identity strategy:
   - Use Bun/server-provided peer-address information if available; or
   - Use a fixed global limiter when no trusted reverse proxy is configured; or
   - Only honor a forwarding header after deployment behind a known trusted proxy that overwrites/removes client-supplied forwarding headers.

3. Ensure the revised throttling mechanism applies consistently to ownership proof, reset-token verification, and MFA verification, and cannot be reset merely by changing browser session, cookie, or request headers.

## DECISION

FAIL