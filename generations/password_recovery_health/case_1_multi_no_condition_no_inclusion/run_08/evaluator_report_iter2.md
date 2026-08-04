## SUMMARY

The artifact is a valid single-file Bun HTTPS SPA with a functional recovery, token verification, password reset, mock MFA, and privacy-acceptance flow. It has strong baseline protections including secure cookies, CSRF tokens, CSP nonces, HTTPS/HSTS, generic recovery responses, Argon2id hashing, and output handling via `textContent`. However, it has security and flow-control defects that prevent acceptance: verification-rate limiting can be bypassed by creating new sessions, and the browser can directly navigate to protected/success screens without completing the corresponding workflow.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun implementation with no build tooling or external assets.**  
  All server logic, HTML, CSS, and browser JavaScript are contained in `app.ts`. It uses Bun directly and does not depend on frameworks, bundlers, external scripts, fonts, or network calls.

- **PASS — TLS certificates are required and used by the HTTPS server.**  
  The application checks for `certs/cert.pem` and `certs/key.pem`, exits if absent, and configures `Bun.serve` with those files.

- **PASS — Plain HTTP is redirected to a fixed HTTPS origin.**  
  The HTTP server returns a fixed `308` redirect to `https://localhost:<HTTPS_PORT>` and does not construct the redirect origin from attacker-controlled request headers.

- **PASS — Security headers are configured.**  
  The HTTPS HTML response includes HSTS, CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, and `Cache-Control: no-store`.

- **PASS — CSRF protections are present for state-changing API operations.**  
  State-changing API routes require a session cookie and session-specific CSRF token. The client sends the token in `X-CSRF-Token`, and the server validates it. The session cookie is `Secure`, `HttpOnly`, and `SameSite=Strict`.

- **PASS — Sensitive API operations enforce server-side workflow state.**  
  `/api/reset` requires a verified reset flow, `/api/mfa` requires a completed password reset, and `/api/privacy` requires authenticated MFA state. The server does not accept user/patient identifiers for privacy acceptance.

- **FAIL — Token-verification rate limiting can be bypassed by starting new sessions.**  
  The verification limiter key is `${clientIp(request)}:${session.id}`. An attacker can obtain a fresh session cookie and receive five new attempts for the same IP, defeating the stated protection against new-session bypasses. The code comment claiming this limiter “resists new-session bypasses” is inaccurate.

- **PASS — Recovery request throttling includes an IP-level control.**  
  `/api/recovery` applies both session-level and IP-level limits. It does not disclose whether an account exists.

- **PASS — Reset tokens are cryptographically random, opaque, short-lived, and single-use.**  
  Tokens are generated using `crypto.getRandomValues`, are 64 hex characters, expire after 15 minutes, and are marked used immediately upon successful verification.

- **PASS — Manual token submission and simulated delivery work.**  
  The reset token is returned by the mock API, saved in the client, logged through browser `console.log`, displayed in the visible Logs panel, and may also be entered manually in the verification form.

- **PASS — Password policy and password hashing are implemented.**  
  Passwords require at least 12 characters and lowercase, uppercase, numeric, and symbol characters. The final password value is stored only as an Argon2id hash via `Bun.password.hash`.

- **PASS — MFA is implemented as a deterministic simulated factor with lockout.**  
  The mock MFA code is returned to the browser, written to browser console logs, and incorrect code attempts are limited to five per recovery flow.

- **PASS — XSS protections are generally appropriate for the vanilla implementation.**  
  Dynamic client values are inserted using `textContent` rather than `innerHTML`; user inputs are not reflected by the server; CSP uses a per-page nonce; no untrusted external script is loaded.

- **PASS — Anti-phishing guidance is provided.**  
  The request screen explicitly tells users that staff will not request passwords or MFA codes by email or phone and instructs users to use the hospital page directly.

- **FAIL — SPA hash routes permit inaccurate access to protected workflow screens.**  
  A user can directly visit `#reset`, `#mfa`, `#privacy`, or `#complete` because `render()` only checks whether the hash is in the route list. In particular, `#complete` displays “Your password reset and privacy-condition acceptance have been recorded” before either action occurred. The APIs prevent state changes, but the UI exposes misleading protected/success states and does not accurately enforce flow progression.

- **FAIL — Verified recovery-flow expiry is not enforced after password reset.**  
  `verifiedFlowExpiresAt` is enforced by `/api/reset`, but not by `/api/mfa`. A user can verify a token and reset the password, wait beyond the ten-minute verified-flow lifetime, then still submit the static MFA code and authenticate as long as the eight-hour session remains active. This contradicts the intended short-lived verified reset-flow state.

## FAILING_ITEMS

- Verification throttling is keyed by both IP and session ID, so a new session resets the verification-attempt budget for the same network.
- Browser hash navigation allows direct display of reset, MFA, privacy, and completion screens without the required successful server-backed flow state. The completion page can falsely state that changes were recorded.
- The ten-minute `verifiedFlowExpiresAt` limit is not checked by `/api/mfa`, allowing an expired recovery flow to continue after the password-reset endpoint has completed.

## NEW_TASKS

1. Change `/api/verify` rate limiting to use an IP-based key that is not session-specific, or combine independent IP and session limits so creating a new session cannot reset the network-level verification attempt budget.

2. Enforce `verifiedFlowExpiresAt` in `/api/mfa`; when expired, clear the recovery flow and return a clear error requiring a new recovery request. Ensure subsequent state-dependent recovery endpoints use consistent expiration handling.

3. Add client-side route guards so `#reset`, `#mfa`, `#privacy`, and `#complete` are only rendered after the corresponding successful workflow transitions. On invalid direct navigation, return the user to the appropriate earlier screen and do not display completion language unless `/api/privacy` has succeeded.

## DECISION

FAIL