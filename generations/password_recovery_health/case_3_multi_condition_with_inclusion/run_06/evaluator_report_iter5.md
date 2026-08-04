## SUMMARY

The artifact is a single-file Bun application with a functional recovery, MFA, password-change, login, and privacy-acceptance flow. It generally implements the requested low-distraction UI, browser-side mock logging, HTTPS/TLS, security headers, CSRF tokens, bcrypt password hashing, and server-side session/account binding. However, it does not fully meet the security acceptance requirements because recovery-request/MFA-send actions are not actually rate-limited, and expired reset records can still be used for MFA actions, producing misleading success responses after expiry.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no build tools or external assets.**  
  `app.ts` contains the Bun server, generated HTML, CSS, client JavaScript, API logic, and in-memory mock data. The browser script is served from the same `app.ts` file at `/app.js`; no framework, bundler, compiler, external script, external stylesheet, or network service is used.

- **PASS — HTTPS is configured using the prescribed certificate paths and HTTP redirects to HTTPS.**  
  The server reads `certs/cert.pem` and `certs/key.pem`, starts TLS on port `3443`, and redirects HTTP port `3000` to `https://localhost:3443`.

- **PASS — Recovery flow is functional and supports both simulated link and manual token entry.**  
  A recovery request issues a random reset token, the browser logs it and exposes an “Open simulated recovery link” button, and the code can also be manually entered in the recovery-code form.

- **PASS — Recovery flow has clear multi-step orientation and ADHD-supportive UX.**  
  The UI provides five visible steps, a progress indicator, an orientation message, simple language, no visible countdown, help content, status messages, and browser `localStorage` step persistence. Session state is also restored from `/api/session`.

- **PASS — Password policy and secure password storage are implemented.**  
  Passwords require at least 12 characters, uppercase, lowercase, digit, symbol, and no whitespace. Changed passwords are stored with `Bun.password.hash(..., { algorithm: "bcrypt" })`; plaintext passwords are not logged or stored.

- **PASS — Login, password change, privacy acceptance, and logout routes enforce server-side session ownership.**  
  Password changes are tied to the reset record’s internal account ID. Privacy acceptance requires `authenticated(session)`. The browser does not submit an account ID or private account identifier.

- **PASS — CSRF protection exists on state-changing routes.**  
  POST routes use `guarded()`, require a session, parse JSON safely, and validate a per-session `X-CSRF-Token` header. Session cookies use `HttpOnly`, `Secure`, and `SameSite=Strict`.

- **PASS — XSS and unsafe output handling are reasonably addressed for this fixed-template application.**  
  The server does not interpolate user-controlled values into HTML. Browser log entries use `textContent`, not `innerHTML`. CSP restricts scripts to same-origin `/app.js`, and the application does not load untrusted scripts.

- **PASS — Security headers and caching controls are configured.**  
  HTTPS responses include HSTS, CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`, and no-store cache headers.

- **FAIL — Reset expiry is not enforced consistently throughout reset/MFA operations.**  
  `/api/mfa/send` and `/api/mfa/verify` do not check `r.expiresAt <= Date.now()`. A reset record can expire, but those endpoints can still respond successfully if its token was previously verified. The subsequent password-change request fails, which creates an inconsistent and confusing flow and does not fully validate reset state securely.

- **FAIL — Recovery-request and MFA-send operations are not actually throttled.**  
  `/api/recovery/request`, `/api/recovery/request-another`, and `/api/mfa/send` call `allowed()`, but no successful-request counter is incremented and no failure count is recorded for repeated requests. Therefore, `allowed()` remains true indefinitely for these actions unless unrelated failure state already exists. This permits unlimited recovery-request and MFA-send requests.

- **FAIL — Brute-force/abuse mitigation is incomplete for all relevant authentication-related actions.**  
  Reset-token verification, MFA verification, and login failures are throttled, but recovery message issuance and MFA-code issuance can be repeatedly triggered without a functioning per-session or global request limit. This does not fully satisfy the requirement to throttle/block automated authentication and reset abuse.

- **PASS — No open redirect or SSRF path is present.**  
  Navigation targets are hard-coded same-origin paths (`/recovery`, `/login`, `/privacy`), and the server makes no outbound network requests.

- **PASS — Safe authentication guidance is visible.**  
  The help panel states that hospital staff will never request passwords or security codes and tells users to verify `https://localhost` before entering a code.

## FAILING_ITEMS

- **Expired reset records remain usable for MFA-send and MFA-verify API calls.**  
  `POST /api/mfa/send` and `POST /api/mfa/verify` validate reset ownership and prior token verification, but do not validate the reset expiration timestamp. This can produce a false “security code confirmed” success state after a reset has expired.

- **Recovery request throttling is non-functional.**  
  `allowed()` only checks existing counters and lock timestamps. `/api/recovery/request` and `/api/recovery/request-another` never increment an attempt/request counter for successful requests, so repeated requests are never locked.

- **MFA-send throttling is non-functional.**  
  `/api/mfa/send` calls `allowed(g.session, "mfa-send")` nowhere and does not count sends. An authenticated reset session can repeatedly request MFA codes without a limit.

- **The generic failure messaging masks expired-reset state after MFA completion.**  
  Since MFA verification can incorrectly return success after expiration, the user reaches password change and then receives a generic failure. This conflicts with the requirement for clear feedback and a forgiving, structured recovery experience.

## NEW_TASKS

1. Add an expiry check (`r.expiresAt > Date.now()`) to `/api/mfa/send` and `/api/mfa/verify`; reject expired reset records with a clear response indicating that the recovery code expired and that a new recovery request is needed.

2. Implement a request-rate limiter that increments on every recovery request, recovery reissue request, and MFA-send request, with per-session and global limits and a defined lock/retry period.

3. Apply the new rate limiter to `POST /api/recovery/request`, `POST /api/recovery/request-another`, and `POST /api/mfa/send`.

4. Return a specific, non-sensitive expired-recovery status to the browser and update the recovery UI to direct the user back to step 1 when that status is received.

## DECISION

**FAIL**