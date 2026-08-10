## SUMMARY

The artifact is a valid single-file Bun/TypeScript SPA with TLS setup, responsive mobile UI, server-side session ownership checks, CSRF tokens, secure headers, encrypted TOTP seeds, hashed recovery codes, and browser-console mock logging. However, it does not fully meet the verification and lockout requirements: generated backup codes cannot be redeemed because their stored hash format differs from the submitted normalized format, and verification lockouts can be bypassed by restarting the relevant flow.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no frameworks, build tools, external assets, or external network calls.**  
  The server, HTML, CSS, and browser JavaScript are all contained in `app.ts`. It uses `Bun.serve`, imports only Node’s built-in filesystem module, and does not use bundlers, frameworks, databases, or remote resources.

- **PASS — TLS/HTTPS is configured using the required certificate locations.**  
  The app reads `certs/cert.pem` and `certs/key.pem`, starts the primary Bun listener with `tls`, and refuses startup when the certificates are absent. A separate HTTP listener redirects requests to HTTPS.

- **PASS — Responsive, mobile-oriented, accessible-enough SPA UI is implemented.**  
  The page includes a mobile viewport tag, constrained mobile card layout, readable text and control sizes, semantic form elements, labels, focus styles, `aria-live`, and `role="alert"` error areas.

- **PASS — MFA endpoints enforce authenticated session ownership and prevent IDOR.**  
  Protected MFA endpoints obtain the user only from `session.userId`, never from client-provided IDs. `bodyOf()` rejects payloads containing `userId` or `accountId`, preventing direct user/account identifier manipulation.

- **PASS — State-changing requests use CSRF protections.**  
  Sign-in, identity verification, MFA setup, MFA verification, recovery-code verification, recovery-code regeneration, and logout require the request’s `X-CSRF-Token` to match the server-side session token. Session cookies use `SameSite=Strict`.

- **PASS — Session cookies have appropriate security attributes.**  
  Cookies are set with `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, and an absolute `Max-Age`.

- **PASS — Security response headers are substantially implemented.**  
  HTTPS responses include CSP with a per-page nonce, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, and `Cache-Control: no-store`.

- **PASS — CORS is restricted to configured trusted HTTPS localhost origins.**  
  Only configured origins receive CORS response headers. Requests with an untrusted `Origin` are rejected.

- **PASS — OTP seed is encrypted at rest and recovery codes are not stored in plaintext.**  
  TOTP seeds are encrypted using AES-GCM with a random in-memory encryption key. Recovery codes are stored as peppered SHA-256 hashes rather than plaintext.

- **PASS — Cryptographically secure randomness is used for secrets, sessions, CSRF tokens, TOTP seeds, and recovery codes.**  
  The artifact uses `crypto.getRandomValues()` for random values.

- **PASS — No OTP seeds, OTPs, backup codes, or session tokens are written to server logs or browser storage.**  
  There is no use of `localStorage` or `sessionStorage`. Server-side logging only prints the application URL. Testing values are intentionally sent to the browser and logged by browser JavaScript, as required.

- **PASS — Input validation and output handling are generally safe.**  
  Email, phone, OTP, and recovery-code inputs are normalized and validated server-side. Dynamic secret and recovery-code rendering uses `textContent`, avoiding DOM XSS in those values. API errors are generic.

- **PASS — Redirect handling is allow-listed.**  
  The supplied `destination` is accepted only when it is exactly `"/"`, preventing open redirects.

- **PASS — Session rotation and expiry handling are implemented.**  
  Sessions rotate after sign-in and successful identity verification. Idle and absolute expiration are checked on each active-session lookup. Logout deletes the server-side session and clears the cookie.

- **FAIL — Recovery codes do not function after generation.**  
  `backupCode()` generates values containing a hyphen, for example `ABCDE-FGHIJ`. During generation, the server stores `protectedHash(codes)` using the hyphenated form. During verification, `normalizeBackup()` removes the hyphen before hashing. Therefore the submitted hash never equals the stored hash, and every valid displayed recovery code is rejected.

- **FAIL — TOTP verification lockout can be bypassed.**  
  After five failed TOTP verification attempts, `/api/mfa/verify` sets `totpLockedUntil`. However, calling `/api/mfa/begin` immediately resets `totpFailures` to `0` and `totpLockedUntil` to `undefined`. An authenticated user can repeatedly call the begin endpoint to evade the lockout.

- **FAIL — Identity-verification lockout can be bypassed by starting sign-in again.**  
  Identity failures and `identityLockedUntil` are stored only in the current session. `/api/auth/signin` rotates to a new identity session with `identityFailures: 0`, allowing a user to bypass a five-attempt lockout simply by restarting sign-in. A newly created session can also bypass the lockout entirely.

- **FAIL — Existing MFA-enabled users are routed to authenticator setup after identity verification instead of their MFA status.**  
  The identity-verification response contains `mfaEnabled`, but the client always calls `setup()` after `/api/auth/identity` succeeds. A user who already has MFA enabled is therefore directed to “Set up your authenticator” rather than the MFA status page, where the UI otherwise supports recovery-code testing and regeneration.

## FAILING_ITEMS

- Generated backup recovery codes are unusable because generation hashes the hyphenated value while verification hashes the de-hyphenated normalized value.
- The TOTP failure lockout is reset by `/api/mfa/begin`, allowing unlimited retry cycles.
- The identity-code failure lockout is session-scoped and can be bypassed through another sign-in/session rotation.
- The post-identity client routing ignores `mfaEnabled`, causing existing enrolled users to enter setup rather than view their MFA status.

## NEW_TASKS

1. Normalize recovery codes identically before both storage and verification. For example, hash `normalizeBackup(code)` during generation, or preserve the hyphen during verification; add a test that a newly displayed recovery code succeeds once and fails on its second use.

2. Preserve and enforce TOTP lockout state when `/api/mfa/begin` is called. Do not clear `totpFailures` or `totpLockedUntil` merely because a new setup secret is generated; clear failure state only after a successful verification or after the lock period has elapsed under controlled logic.

3. Move identity-verification failure and lockout tracking from the rotating session into server-side state keyed to a normalized identity attempt/account-safe identifier, so a new sign-in or new session cannot bypass the lockout. Keep responses generic to avoid account enumeration.

4. Update the successful `/api/auth/identity` client handler to route with `r.mfaEnabled ? status() : setup()` rather than always invoking `setup()`.

## DECISION

FAIL