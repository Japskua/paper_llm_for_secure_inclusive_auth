## SUMMARY

The artifact is a well-structured single-file Bun HTTPS password-recovery SPA with strong baseline controls: session cookies, per-session CSRF tokens, restrictive headers/CSP nonces, token expiry/single-use handling, bcrypt hashing, password policy, MFA, input validation, and browser-console mocks. However, it does not fully meet the security requirements because rate limits are trivially bypassed by creating a new session, and the client-side hash router allows unauthorised navigation to protected/confirmation UI states without completing the recovery flow.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no build tools, frameworks, or external assets.**  
  The HTML, CSS, browser JavaScript, and Bun server all exist in `app.ts`. It uses `Bun.serve`, imports only Node’s built-in crypto module, and does not require compilation, bundlers, or network assets.

- **PASS — HTTPS is configured using the supplied mkcert certificate paths.**  
  The HTTPS server uses `certs/cert.pem` and `certs/key.pem`. A separate HTTP listener returns a `308` redirect to HTTPS.

- **PASS — Security headers and CSP are substantially configured.**  
  HTTPS responses include HSTS, CSP with unique nonces, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, cache prevention, permissions policy, COOP, and CORP headers. The CSP prevents third-party resources and limits scripts/styles to server-issued nonces.

- **PASS — CSRF protection is implemented for state-changing API operations.**  
  A cryptographically random CSRF token is generated per session and checked on every POST API route through `requireCsrf`. Cookies use `Secure`, `HttpOnly`, and `SameSite=Strict`.

- **PASS — Reset tokens are random, session-bound, short-lived, and single-use.**  
  Tokens use `randomBytes`, are stored as SHA-256 hashes, expire after ten minutes, are associated with the session, and are marked used after a successful password reset.

- **PASS — The reset flow works through both a simulated verification link and manual entry.**  
  The recovery request returns the mock token, logs it through browser-side `console.log`, creates a functional `/verify?token=...` link, pre-populates the verification form from that link, and also allows manual token submission.

- **PASS — Sensitive account/patient identifiers are not exposed.**  
  The application does not disclose a username, patient name, course folder, account existence, or other private account identifiers. Recovery responses are generic.

- **PASS — Inputs are constrained and dynamic user-controlled text is not injected as HTML.**  
  Identifiers, reset tokens, MFA codes, and passwords are server-validated. Browser messages and logs are written with `textContent`, not `innerHTML`, preventing reflected DOM XSS through submitted values.

- **PASS — Password policy and bcrypt password hashing are implemented.**  
  The server requires a 12+ character password with upper/lowercase letters, a digit, and a symbol. Passwords are processed with `Bun.password.hash(..., { algorithm: "bcrypt" })` and are not logged or persisted as plaintext.

- **PASS — MFA is present and verified before privacy acceptance.**  
  After password reset, a deterministic mock MFA code is returned only for browser-side mock logging. The MFA value expires and verification is required before the privacy-acceptance API succeeds.

- **FAIL — Brute-force/request throttling can be bypassed by starting a new session.**  
  `recoveryAttempts`, `tokenAttempts`, and `mfaAttempts` are stored only on the cookie-backed session. An attacker can delete/change their cookie or make requests without retaining cookies to receive a new session and reset each counter. This does not robustly satisfy the requirement that automated guessing attempts be throttled or blocked.

- **FAIL — Client-side routing permits unauthorised access to flow states and a false completion screen.**  
  The `route()` function accepts any known hash, such as `/#password`, `/#privacy`, `/#appointment`, or `/#complete`, and `show()` displays that UI without checking whether the required server-side recovery state has been reached. Most API calls still reject unauthorised actions, but directly visiting `/#complete` displays “Appointment request received” even when no appointment was requested. This is an inaccurate confirmation state and weakens the access-control/flow-integrity UX.

- **PASS — Sensitive server API actions enforce server-side state checks and avoid IDOR.**  
  The APIs do not accept user or patient IDs from the client. Password reset, MFA, privacy acceptance, and appointment request endpoints each enforce the required session state.

- **PASS — No external URLs, outgoing requests, or open redirects are present.**  
  Browser fetches are same-origin API calls only. The HTTP redirect has a fixed local HTTPS destination and does not reflect user-controlled redirect parameters.

- **PASS — Safe-authentication guidance is displayed.**  
  The interface warns users not to share passwords or recovery codes with staff over email or phone and advises them to use their trusted hospital address.

## FAILING_ITEMS

- Session-only rate limits are bypassable. A requester can obtain a new `recovery_session` and thereby reset the recovery, token-verification, and MFA attempt counters. This leaves the application without meaningful protection against automated request flooding and makes the nominal brute-force controls ineffective across sessions.

- The hash-based SPA router exposes protected UI steps without a completed flow. For example, opening `https://localhost:3000/#complete` immediately shows an “Appointment request received” confirmation, even though the protected appointment API was never successfully called.

## NEW_TASKS

1. Replace session-only throttling with server-side rate-limit tracking that cannot be reset by obtaining a new session. Apply it at minimum to recovery requests, token verification failures, and MFA verification failures; use bounded, expiring records keyed by an appropriate server-observed requester key and/or a securely derived identifier key. Ensure rate-limit responses remain generic and do not reveal account existence.

2. Implement a client-side flow-state guard for the SPA router. Only allow `password`, `mfa`, `privacy`, `appointment`, and `complete` views after their respective successful API transitions in the current browser flow; route direct or invalid hash navigation back to the recovery request screen.

3. Ensure the completion view is displayed only after a successful `/api/request-appointment` response. Direct navigation to `/#complete` must not show an appointment-recorded confirmation.

## DECISION

FAIL