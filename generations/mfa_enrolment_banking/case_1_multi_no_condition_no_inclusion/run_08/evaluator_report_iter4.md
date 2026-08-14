## SUMMARY

The artifact is a valid single-file Bun/TypeScript SPA with inline HTML, CSS, and vanilla browser JavaScript. It implements TLS, secure headers, HttpOnly/Secure/SameSite cookies, server-side session checks, CSRF checks, TOTP generation/verification, recovery-code generation and consumption, encrypted in-memory secret storage, and mobile-oriented UI styling. However, the authenticated returning-user/recovery-code UI flow is faulty: recovery codes are not loaded after a refresh or subsequent sign-in, and a returning MFA-enabled user is incorrectly put back into enrolment, allowing generation of a replacement authenticator secret.

## FUNCTIONAL_CHECK

- **PASS — Single-file, no-framework, no-build implementation**
  - The complete server, HTML template, CSS, and browser-side vanilla JavaScript are contained in `app.ts`.
  - It uses Bun’s direct TypeScript execution and built-in Node-compatible modules only; no bundlers, compilers, external assets, or network calls are used.

- **PASS — TLS/HTTPS server configuration**
  - `Bun.serve` is configured with `tls: { cert, key }` using `certs/cert.pem` and `certs/key.pem`.
  - HSTS is set on responses, and forwarded HTTP traffic is rejected when `x-forwarded-proto` is explicitly `http`.

- **PASS — Secure response headers and CORS restrictions**
  - Responses include CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, referrer policy, permissions policy, and `Cache-Control: no-store`.
  - CORS is only enabled for configured localhost development origins.

- **PASS — Secure session handling and authorization**
  - Sessions are obtained from an HttpOnly/Secure/SameSite=Strict cookie.
  - MFA endpoints use `requireAuth`, which verifies that the session belongs to the fixed account owner.
  - Request bodies reject `accountId` and `userId`, preventing client-supplied ownership targeting/IDOR attempts in this mock.
  - Session IDs are rotated when a pre-auth session signs in, and authenticated sessions enforce idle and absolute expiry.
  - Logout invalidates the server session and clears the cookie.

- **PASS — CSRF protection on state-changing authenticated operations**
  - MFA identity confirmation, setup, verification, recovery-code regeneration, recovery-code use, and logout require the per-session CSRF token.
  - Sign-in also requires the pre-auth session’s CSRF token.

- **PASS — Input validation and safe client rendering**
  - Email, phone, OTP, and recovery code formats are server-validated.
  - JSON body shape and content type are checked.
  - Dynamic browser-rendered values such as TOTP secrets and recovery codes are assigned with `textContent` or DOM node creation rather than interpolated into dynamic HTML.

- **PASS — TOTP and recovery-code security behavior**
  - TOTP shared secrets are generated using `randomBytes`, encrypted with AES-256-GCM in server memory, and verified using HMAC-SHA1 TOTP with a time window.
  - TOTP values are replay-protected through `acceptedCounter`.
  - Recovery codes are cryptographically generated, encrypted at rest in server memory, time-bound, and removed after successful use.
  - OTP and recovery-code failures are rate-limited and lock the account for ten minutes after five failures.

- **PASS — MFA enrolment and simulated delivery for a first-time user**
  - The first-time flow supports sign-in, identity confirmation, manual TOTP secret provisioning, simulated OTP display, OTP verification, MFA enablement, and initial recovery-code display.
  - The simulated TOTP secret, TOTP code, and recovery codes are returned to the UI and logged with browser-side `console.log`, as explicitly required for the mock.

- **PASS — Mobile UI and semantic structure**
  - The UI includes viewport configuration, responsive maximum-width layout, mobile-friendly controls, readable typography, and a small-screen media query.
  - It uses semantic elements including `main`, `header`, `section`, `form`, `label`, `button`, and headings.

- **FAIL — Recovery-code management works after page refresh or returning sign-in**
  - `boot()` can call `confirmed()` for an already MFA-enabled authenticated session, but `delivery.codes` remains empty.
  - `recovery()` renders only `delivery.codes`; it never calls the existing authenticated endpoint `GET /api/mfa/recovery`.
  - Therefore, clicking “View recovery codes” after a refresh, restored authenticated session, or later sign-in shows an empty list even when encrypted recovery codes exist server-side.

- **FAIL — Returning MFA-enabled users are incorrectly sent through enrolment and can replace their authenticator**
  - After successful `/api/auth/signin`, `signIn()` always calls `identity()` rather than checking `/api/mfa/status`.
  - For an already enrolled user, this permits progressing to `/api/mfa/setup`, which creates and stores a new TOTP secret and resets replay state.
  - The flow should route an MFA-enabled user to the confirmed/settings state instead of silently restarting authenticator enrolment.

- **PASS — Internal links and controls in the initial flow**
  - The cancel/sign-out, back, recovery, regeneration, and logout controls are wired to browser handlers.
  - However, the recovery management page has the data-loading defect described above.

## FAILING_ITEMS

- **Recovery codes are not fetched when opening recovery-code management from an existing MFA session.**
  - `recovery()` uses only client-memory `delivery.codes`.
  - After `boot()` restores an MFA-enabled session and calls `confirmed()`, that array is empty.
  - The server already exposes `GET /api/mfa/recovery`, but the UI does not use it.

- **The post-sign-in route ignores existing MFA state.**
  - `signIn()` immediately invokes `identity()` after obtaining an authenticated session.
  - It must instead request MFA status and route based on `mfaEnabled` and `identityConfirmed`.
  - Current behavior permits an MFA-enabled user to create a replacement TOTP secret through the ordinary enrolment path.

## NEW_TASKS

1. **Load current recovery codes in the recovery screen.**
   - Update `recovery()` to call `GET /api/mfa/recovery` before rendering the code list.
   - Populate `delivery.codes` from the response and show a generic UI error if loading fails.
   - Continue refreshing the list after a recovery code is consumed or regenerated.

2. **Route users according to server-side MFA status immediately after sign-in.**
   - After `/api/auth/signin` succeeds and the CSRF token is updated, call `/api/mfa/status`.
   - Route to `confirmed()` when `mfaEnabled` is true, to `setup()` when identity is already confirmed but MFA is not enabled, and to `identity()` otherwise.
   - Ensure ordinary sign-in does not restart or overwrite an already enabled authenticator.

## DECISION

FAIL