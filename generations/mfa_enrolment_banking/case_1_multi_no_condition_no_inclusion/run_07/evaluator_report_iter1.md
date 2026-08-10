## SUMMARY

The artifact is a valid single-file Bun/TypeScript SPA with inline HTML, CSS, and browser-side vanilla JavaScript. It correctly uses TLS certificates, hardened headers, secure cookie attributes, CSRF validation, cryptographic randomness, encrypted MFA material, and an operational simulated OTP/recovery-code flow. However, it does not fully satisfy the required MFA flow and authentication-failure controls: recovery-code verification is not rate-limited or locked out, prior sessions are not invalidated when a fresh session is issued, and client routing can falsely display “MFA is active” before MFA and recovery codes have actually been completed.

## FUNCTIONAL_CHECK

- **PASS — Single-file delivery and zero-compilation compliance.**  
  The server, HTML, CSS, and vanilla browser JavaScript are all contained in `app.ts`. There are no frameworks, package imports, build tools, bundlers, or external assets.

- **PASS — Bun serves the application over TLS using the specified certificate paths.**  
  `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`. The server only starts with TLS configured.

- **PASS — Mobile-responsive UI is present.**  
  The UI has a viewport meta tag, constrained mobile-width layout, readable typography, large form controls, and a narrow-screen media query that makes buttons full-width.

- **PASS — Semantic and accessible-enough enrolment UI exists.**  
  The app uses `header`, `main`, `section`, `nav`, `footer`, form labels, headings, and `aria-live`.

- **PASS — Sign-in, identity confirmation, provisioning, OTP verification, recovery-code generation, redemption, and logout endpoints exist.**  
  The endpoint set supports the intended simulated flow.

- **PASS — Simulated provisioning values are returned to the protected browser UI and browser console.**  
  `/api/mfa/provision` returns a manually usable secret and deterministic mock OTP. Browser-side `console.log` displays these test-only values, as explicitly required by the deliverable.

- **PASS — Backup codes are generated with a cryptographically secure RNG and displayed in the browser UI/console for testing.**  
  `crypto.getRandomValues` is used and recovery codes are returned to the authenticated browser for the required mock flow.

- **PASS — MFA data is protected at rest in server memory.**  
  The TOTP secret and recovery-code plaintext are AES-GCM encrypted. Recovery codes also have SHA-256 comparison hashes for redemption.

- **PASS — MFA endpoints derive ownership from the authenticated server session rather than client-provided account IDs.**  
  The account is derived from `bank_session`; supplied `userId`, `accountId`, and `email` identifiers are rejected for MFA API routes.

- **PASS — CSRF protection is applied to authenticated state-changing requests.**  
  MFA mutation endpoints and logout require a session-bound CSRF token and a same-origin HTTPS `Origin` value.

- **PASS — Session cookies have required security attributes.**  
  The session cookie is issued with `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, and `Max-Age`.

- **FAIL — Session rotation does not invalidate an existing session ID.**  
  Login creates a new session ID, but does not delete a pre-existing `bank_session` token from the `sessions` map. A previously issued authenticated session remains valid until timeout/logout. This is incomplete session-rotation behavior and weakens protection against session fixation/session theft.

- **PASS — Idle and absolute session timeouts are enforced server-side.**  
  `authenticated()` checks both 15-minute idle timeout and 8-hour absolute timeout.

- **PASS — Logout invalidates the active session and clears the browser cookie.**  
  The session map entry is deleted and a secure expired cookie is returned.

- **PASS — Secure response headers are set.**  
  Responses include CSP with `frame-ancestors 'none'`, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, referrer policy, and permissions policy.

- **PASS — CORS is limited to the local trusted HTTPS origin.**  
  CORS headers are emitted only where `Origin` exactly matches `https://${host}` and the host matches the localhost allow-list.

- **PASS — Server errors are generic and do not expose stack traces.**  
  The top-level server handler catches exceptions and returns a generic JSON error.

- **PASS — Inputs are validated server-side.**  
  Email, phone, OTP, and recovery-code formats are validated; JSON requests are required for mutation requests.

- **PASS — Output is escaped before insertion into browser HTML.**  
  Dynamic values rendered into `innerHTML` are passed through `escapeHtml`; server-provided error text is also escaped.

- **PASS — No open redirects are implemented.**  
  Navigation is hash-based and routes are selected from fixed internal page names.

- **PASS — Provisioning OTP verification is time-bound and cannot be successfully reused after enabling MFA.**  
  Provisioning expires after five minutes, accepts only current/previous time windows, and marks the pending provision as used after successful verification.

- **PASS — Failed TOTP-enrolment verification is rate-limited/locked.**  
  After five failed OTP attempts, provisioning is locked for ten minutes.

- **FAIL — Failed recovery-code redemption attempts are not rate-limited or locked out.**  
  `/api/mfa/recovery/redeem` allows unlimited invalid recovery-code submissions. Recovery-code redemption is also a verification action and should receive equivalent throttling/lockout controls.

- **FAIL — The UI can claim MFA is active even when MFA is not enabled.**  
  A user can manually navigate to `#complete` after login, or use the “Skip for now” link on the recovery page. `completePage()` always renders “MFA is active” without checking `/api/me` state. This is an incorrect and misleading MFA-enrolment state.

- **FAIL — The required recovery-code storage step can be skipped.**  
  The recovery page has a `#complete` “Skip for now” link, allowing the flow to end without generating and storing recovery codes, despite the stated use case requiring Marcus to securely store a set of backup recovery codes.

- **FAIL — Recovery-code redemption is not server-gated on MFA being enabled.**  
  `/api/mfa/recovery/redeem` checks authentication, CSRF, and code format, but does not require `auth.account.mfaEnabled`. It should reject this MFA operation unless MFA is active, consistent with the recovery-code view/generation endpoint protections.

- **PASS — No compile-time or obvious Bun runtime syntax errors were identified.**  
  The TypeScript uses Bun-supported APIs and the top-level `await`, Web Crypto APIs, `Bun.file`, and `Bun.serve` usage are structurally valid.

## FAILING_ITEMS

- Login issues a fresh session token but leaves any previously presented authenticated session token valid in the server session map.
- Recovery-code redemption accepts unlimited failed guesses; it has no attempt counter, rate limit, or temporary lockout.
- The client-side router does not enforce server-confirmed MFA state before rendering the completion screen.
- The recovery-code step offers a “Skip for now” path, so the intended enrolment flow can end without backup codes being generated/stored.
- The recovery-code redemption endpoint does not verify `auth.account.mfaEnabled` before processing a recovery code.

## NEW_TASKS

1. On successful `/api/login`, parse and delete any existing `bank_session` token before creating and issuing the new session token.

2. Add per-account or per-session recovery-code redemption failure tracking with a bounded attempt count and temporary lockout; return the same generic invalid-code response during lockout to avoid information leakage.

3. Require `auth.account.mfaEnabled` in `/api/mfa/recovery/redeem`, returning a generic forbidden/error response if MFA is not enabled.

4. Return sufficient enrolment state from `/api/me`—at minimum `mfaEnabled`, `identityConfirmed`, and whether recovery codes exist—and enforce those states in `route()` before rendering `provision`, `verify`, `recovery`, or `complete`.

5. Remove the recovery page’s “Skip for now” link and only permit navigation to `#complete` after recovery codes have been generated and the user has confirmed that they saved them.

6. Make `completePage()` verify current server state before rendering the “MFA is active” success message; otherwise route the user to the correct incomplete enrolment step.

## DECISION

**FAIL**