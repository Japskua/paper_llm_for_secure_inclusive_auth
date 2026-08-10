## SUMMARY

The artifact is a valid single-file Bun application with inline HTML, CSS, and vanilla browser JavaScript. It implements a mobile-friendly MFA enrolment flow, TLS, CSP and other security headers, CSRF tokens, secure cookies, encrypted TOTP secrets, hashed recovery codes, expiry, session rotation, and functional simulated verification flows. However, it does not fully satisfy the access-control and rate-limiting requirements: arbitrary valid email/phone input can authenticate as Marcus, the CORS/origin trust check accepts arbitrary HTTPS localhost ports, and verification lockouts can be bypassed by restarting flows.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun server with no build tooling or external assets**
  - Everything is contained in `app.ts`, including the Bun server, HTML, CSS, and client-side JavaScript.
  - It uses `Bun.serve` directly and does not require frameworks, bundlers, or network assets.

- **PASS — TLS/HTTPS support and HSTS**
  - The Bun server is configured with `certs/cert.pem` and `certs/key.pem`.
  - No separate HTTP listener is created.
  - `Strict-Transport-Security` is applied through `headersFor`.

- **PASS — Mobile-responsive and legible UI**
  - The page includes a mobile viewport meta tag.
  - The CSS uses a constrained responsive layout, touch-friendly controls, readable font sizing, responsive media rules, focus styles, and semantic form labels.

- **PASS — MFA enrolment flow is implemented and interactive**
  - Sign-in, identity verification, authenticator provisioning, TOTP confirmation, recovery-code generation, acknowledgement, settings, regeneration, and logout are implemented.
  - Internal hash navigation routes are handled.
  - Browser-side logs display mock delivery values as required by the explicit demo deliverable.

- **PASS — Manual authenticator-secret and OTP submission is supported**
  - The authenticator secret is returned for the demo and shown through browser logs.
  - The UI supplies manual secret and six-digit OTP fields.
  - Server verification checks that the manually submitted secret equals the encrypted server-side secret.

- **PASS — Cryptographically secure generation and protected at-rest storage**
  - TOTP secrets use `randomBytes(20)` and are encrypted with AES-256-GCM.
  - Recovery codes use `randomBytes` and only SHA-256 hashes are retained server-side.
  - TOTP windows are tracked in `usedWindows`, preventing replay of an accepted OTP time window.

- **PASS — Secure cookie and session handling is mostly implemented**
  - Session cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - Pending sessions are replaced with new authenticated sessions after identity verification, mitigating session fixation.
  - Idle and absolute timeouts are implemented.
  - Logout invalidates the server session and expires the session cookie.

- **PASS — CSRF protection is implemented for state-changing endpoints**
  - State-changing API calls require an `X-CSRF-Token`.
  - The server validates CSRF tokens with timing-safe comparison.
  - Sign-in uses a separate bootstrap CSRF token and cookie.

- **PASS — Security headers and generic error handling are present**
  - CSP, HSTS, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, and `Permissions-Policy` are set.
  - Generic JSON errors are returned without stack traces.
  - The CSP uses per-response script nonces and blocks framing through both CSP and `X-Frame-Options`.

- **FAIL — Server-side account-owner authorization is not actually enforced**
  - `/api/signin` accepts any syntactically valid email and phone number, then always creates a session for `account-marcus`.
  - The deterministic identity code is returned to the caller in the API response and logged by the browser, so any party can submit arbitrary valid contact details, use `246810`, and receive an authenticated Marcus session.
  - This violates the requirement that only the authenticated account owner may access or modify their MFA settings.

- **FAIL — CORS and origin validation trust arbitrary localhost ports**
  - `isTrustedOrigin()` allows every HTTPS origin whose hostname is `localhost`, `127.0.0.1`, or `::1`, regardless of port.
  - For example, `https://localhost:4444` is accepted as trusted and receives `Access-Control-Allow-Origin` plus `Access-Control-Allow-Credentials`.
  - Since cookies are host-based rather than port-based, a malicious HTTPS service on another localhost port could call `/api/me`, obtain the CSRF token, and perform authenticated state-changing actions.
  - Trusted origins must be an explicit allow-list of the actual application origin(s), including port.

- **FAIL — Failed-verification lockouts are bypassable**
  - Identity-verification failures are stored only in a pending session. An attacker can restart `/api/signin` and receive a new pending session with a reset failure counter.
  - Authenticator failures are stored inside `session.authenticator`, but `/api/authenticator/start` replaces that object and resets `failures` and `lockedUntil`.
  - Therefore the required lockout after repeated failed verification attempts is not effective.

- **FAIL — Recovery-code redemption has no failed-attempt rate limit or lockout**
  - `/api/recovery/redeem` permits unlimited invalid recovery-code submissions.
  - Recovery codes are verification credentials and should receive the same repeated-failure protections required for verification codes/OTPs.

## FAILING_ITEMS

- Any user supplying a format-valid email and phone number can authenticate into the hard-coded `account-marcus` account using the client-exposed deterministic code.
- The origin/CORS allow-list accepts arbitrary HTTPS services on `localhost`, `127.0.0.1`, or `::1` at any port, rather than only the application’s configured origin.
- Identity-code lockout is scoped to a disposable pending session and is reset by restarting sign-in.
- Authenticator OTP lockout is reset by calling `/api/authenticator/start`, which overwrites the authenticator state.
- Recovery-code redemption supports unlimited invalid guesses without throttling or lockout.

## NEW_TASKS

1. Replace the unconditional `account-marcus` assignment in `/api/signin` with server-side mock account lookup and identity binding. Only create a pending MFA session for the matching mock account identity; return the same generic response for unrecognised input to avoid account enumeration.

2. Make the deterministic academic identity test code usable only for the matched mock account/session, while preserving the required browser-console simulation. Do not let arbitrary email/phone values result in Marcus’s authenticated session.

3. Replace `isTrustedOrigin()` with an explicit configured origin allow-list, such as only `https://localhost:${PORT}` and any specifically required equivalent loopback origin/port combinations. Reject all other origins, including different localhost ports.

4. Move identity-verification failure counters and lockout state from disposable pending sessions to server-side account- or identity-keyed challenge tracking, so initiating a new sign-in cannot reset a lockout.

5. Store authenticator-verification failure and lockout state independently of the replaceable `Authenticator` provisioning object, and prevent `/api/authenticator/start` from clearing an active lockout.

6. Add failure counting, time-based lockout, and optionally request throttling to `/api/recovery/redeem`; reset the counter only after successful redemption or after the defined lockout policy permits it.

## DECISION

**FAIL**