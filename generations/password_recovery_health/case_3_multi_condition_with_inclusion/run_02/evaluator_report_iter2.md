## SUMMARY

The artifact is a single-file Bun HTTPS SPA with a functioning password recovery, password replacement, login, MFA, privacy acceptance, and appointment confirmation flow. It has strong foundations: Argon2id password hashing, session-bound CSRF tokens, CSP nonces, secure cookies, token expiry/single-use handling, and accessible low-stress UI guidance. However, it does not fully meet the security requirements because the recovery API response reveals whether an account exists, and recovery-request throttling can be bypassed through attacker-controlled forwarded-IP headers.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no framework, bundler, compilation step, or external assets**
  - The server, HTML template, inline CSS, and vanilla browser JavaScript all reside in `app.ts`.
  - The app uses `Bun.serve()` directly and has no imports requiring a bundler or external front-end dependencies.

- **PASS — HTTPS/TLS server setup**
  - Bun is configured with `tls: { cert: CERT, key: KEY }` using `certs/cert.pem` and `certs/key.pem`.
  - Secure response headers include HSTS.

- **PASS — Recovery flow works for provisioned accounts**
  - A known account can request a recovery token, receive the simulated token in the browser response/log, manually paste it, verify it, set a new password, sign in, complete MFA, accept privacy terms, and confirm an appointment.
  - The simulated recovery link (`/?reset=...`) and manual code input both work.

- **PASS — Simulated delivery and verification are browser-visible**
  - Recovery tokens and MFA codes are returned to the client and logged through browser-side `console.log`.
  - The UI also provides an on-page demonstration log.

- **PASS — Recovery tokens are cryptographically random, short-lived, session-bound, and single-use**
  - Tokens are generated with `crypto.getRandomValues`.
  - They expire after 15 minutes, become unusable after password replacement, and are associated with the current server-side session.
  - Token comparisons use `timingSafeEqual` after a length check.

- **PASS — Password policy and secure password storage**
  - Passwords require at least 12 characters and include uppercase, lowercase, numeric, and symbol characters.
  - Passwords are stored using `Bun.password.hash(..., { algorithm: "argon2id" })`.
  - Passwords are not returned or logged.

- **PASS — MFA is implemented**
  - Successful password login requires a six-digit MFA code before authentication is marked complete.
  - MFA codes expire and have attempt limits.

- **PASS — CSRF protections are implemented on state-changing routes**
  - Sensitive POST requests require a session, matching same-origin `Origin`, and a session-specific `X-CSRF-Token`.
  - Cookies use `Secure`, `HttpOnly`, `SameSite=Strict`, and the `__Host-` prefix.

- **PASS — XSS protections are substantially implemented**
  - User-controlled values are not interpolated into server-rendered HTML.
  - Browser log output uses `textContent`, not `innerHTML`.
  - CSP uses per-response nonces and disables default content sources.

- **PASS — Sensitive state changes enforce authorization**
  - Password replacement requires a verified recovery code.
  - Privacy acceptance requires an authenticated MFA-completed session.
  - Appointment confirmation requires authentication and accepted privacy conditions.
  - There are no user-ID route parameters or apparent IDOR-style resource lookups.

- **PASS — Low-stress and ADHD-conscious UX**
  - The UI provides a clear step tracker, explicit “next step” messaging, no countdown-driven UI, pause/resume behavior through server session state, visible feedback, straightforward language, and a persistent help/safety section.
  - Panels avoid overwhelming the user with all steps at once.

- **FAIL — Password recovery request response allows account enumeration**
  - `/api/recovery/request` returns `testToken` and `deliveryPath` only when an account exists.
  - For an unknown identifier, the response contains only the generic message. An attacker can compare JSON response shapes and determine whether an account is provisioned.
  - This conflicts with the requirement that the portal must not expose usernames or private identifiers and undermines secure recovery behavior.

- **FAIL — Recovery request throttling trusts attacker-controlled forwarding headers**
  - `clientAddress()` accepts `x-real-ip` and `x-forwarded-for` directly from any request.
  - A direct attacker can send a different forged `X-Forwarded-For` value per request, creating unlimited distinct throttle keys and bypassing `RECOVERY_MAX_ISSUES`.
  - This means recovery-request abuse protections are not reliable unless the server is explicitly deployed behind, and configured to trust, a controlled reverse proxy.

## FAILING_ITEMS

- The recovery request endpoint exposes account existence through response differences:
  - Known account: `{ ok, message, deliveryPath, testToken }`
  - Unknown account: `{ ok, message }`
  - This enables account enumeration.

- Recovery-request rate limiting is bypassable because `X-Forwarded-For` and `X-Real-IP` are treated as trustworthy client identity values without a trusted-proxy boundary.

## NEW_TASKS

1. Make `/api/recovery/request` return an indistinguishable successful response for both known and unknown identifiers, including the same response fields needed by the demonstration UI.
   - For unknown accounts, create a decoy token/link that is displayed and logged but cannot verify a reset or grant account access.
   - Update the client so it consistently permits continuing to the manual-code step after any successful generic recovery response.

2. Replace untrusted forwarded-header rate-limit identity handling.
   - For direct Bun TLS deployment, use a server-derived address mechanism if available, or use a non-spoofable session/account-based throttle.
   - Only honor `X-Forwarded-For`/`X-Real-IP` when deployment is explicitly configured behind a known trusted proxy that strips client-supplied forwarding headers.

## DECISION

FAIL