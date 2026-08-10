## SUMMARY

The artifact is a single-file Bun SPA with strong coverage of TLS, security headers, secure cookies, CSRF checks, session rotation, server-side account derivation, encrypted OTP secrets, hashed recovery codes, and a responsive accessible mobile UI. However, the primary enrolment flow is currently blocked: the identity-verification endpoints require `identityVerified === true` before the user can send or verify their identity code. It also has bypassable login and identity-verification lockouts because failure counters are scoped only to disposable sessions.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no frameworks, bundlers, compilation, or external assets**
  - The entire server, HTML, CSS, and browser JavaScript are contained in `app.ts`.
  - It uses `Bun.serve()` directly and has no external network calls or package dependencies.

- **PASS — TLS/HTTPS server configuration**
  - The Bun server is configured with `certs/cert.pem` and `certs/key.pem`.
  - Cookies use `Secure`, and HSTS is supplied.
  - This assumes the required certificate files are present at runtime as specified.

- **PASS — Mobile-responsive, semantic, legible UI**
  - The page includes a viewport tag, mobile breakpoints, readable font sizing, responsive button behavior, and accessible form labels.
  - The UI has a clear progression for sign-in, identity confirmation, authenticator setup, OTP verification, recovery-code display, settings, and logout.

- **FAIL — End-to-end identity verification and MFA enrolment flow works**
  - `/api/identity/send` and `/api/identity/verify` call `requireAccount(request, true)`.
  - `requireAccount()` rejects every session where `session.identityVerified` is false:
    ```ts
    if (!session || !session.accountId || !session.identityVerified) return null;
    ```
  - Immediately after sign-in, the fresh session explicitly has `identityVerified: false`.
  - Therefore, the client reaches the identity page but cannot send an identity code, cannot verify identity, and cannot reach MFA setup.

- **PASS — Browser-side mock values are logged and usable**
  - Mock identity codes, authenticator setup secrets/current OTPs, and recovery codes are returned to the browser UI and sent to `console.log()` via `testLog()`.
  - Secrets are not logged by the Bun server.

- **PASS — Manual authenticator provisioning is supported**
  - The provisioning secret is displayed in the setup UI for manual entry into an authenticator application.
  - The verification page allows optional manual-secret confirmation as well as OTP submission.

- **PASS — MFA authorization and IDOR protections are largely server-side**
  - MFA API routes derive the account exclusively from `session.accountId`.
  - The client does not submit an account ID or user ID to MFA endpoints.
  - MFA status, provisioning, verification, recovery-code testing, and regeneration require a valid session-derived account.

- **PASS — CSRF protections for state-changing operations**
  - State-changing endpoints validate an `X-CSRF-Token`.
  - Validation includes a constant-time comparison and trusted same-origin check.
  - Session cookies use `SameSite=Strict`.

- **PASS — Secure response headers and CORS restrictions**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, referrer policy, permissions policy, and no-store cache controls are configured.
  - CORS is only returned for trusted local HTTPS same-origin requests.

- **PASS — Secure session handling**
  - Session cookies are `HttpOnly`, `Secure`, `SameSite=Strict`, path-scoped, and use the valid `__Host-` naming convention.
  - Sessions have idle and absolute expiration checks.
  - Session IDs are rotated after sign-in.
  - Logout invalidates the server-side session and expires the cookie.

- **PASS — OTP secret and recovery-code protection**
  - Authenticator secrets are generated with `crypto.getRandomValues()` and stored encrypted with AES-GCM.
  - Recovery codes are generated using cryptographic randomness and stored as digests with a server-side pepper.
  - Browser storage APIs are not used for session tokens or secrets.

- **PASS — OTP/recovery-code expiry and one-time behavior**
  - Identity codes expire after five minutes and are marked used after successful verification.
  - Pending authenticator setup expires after ten minutes and is marked used after successful MFA setup.
  - Recovery codes are marked used on successful verification.
  - TOTP codes are tied to the current 30-second period.

- **FAIL — Rate limiting/lockout is not robust against new-session bypasses**
  - Failed sign-in attempts increment `session.failedLogin`, and failed identity attempts increment `session.failedIdentity`.
  - An attacker can obtain a fresh anonymous session through `/api/csrf`, then repeat attempts with a new session after each five-attempt lockout.
  - The account-level MFA lockout is better protected because `failMfa()` sets `account.mfaLockedUntil`, but login and identity checks lack equivalent server-side account/rate-limit-key state.
  - This does not fully meet the requirement to rate-limit and lock out repeated failed verification/authentication attempts.

- **PASS — Input validation and output handling**
  - Email, phone number, OTP, and recovery-code inputs are validated server-side.
  - API responses are JSON and rendered values such as secrets and recovery codes are inserted using `textContent`.
  - No user-controlled values are interpolated into HTML templates.

- **PASS — Generic error handling and enumeration-resistant messaging**
  - The API generally returns generic error messages rather than exposing whether an account, code, or credential was valid.
  - The server catch block returns a generic error instead of a stack trace.

## FAILING_ITEMS

- The identity-verification stage is impossible to complete because `requireAccount()` requires `session.identityVerified` for `/api/identity/send` and `/api/identity/verify`, while identity verification is precisely what sets that flag to `true`.

- Login lockout is session-scoped only. A new session can be created through `/api/csrf`, allowing repeated sign-in attempts after discarding a locked session.

- Identity-code verification lockout is session-scoped only. A user or attacker can sign in again to obtain a fresh session and reset `failedIdentity`.

## NEW_TASKS

1. Split authenticated-account authorization from identity-verified MFA authorization. Add a helper that requires only a valid authenticated session and session-owned account, then use it for `/api/identity/send` and `/api/identity/verify`; retain the identity-verified requirement for MFA provisioning, MFA verification, recovery-code operations, and settings.

2. Implement server-side login throttling/lockout that cannot be reset by creating a new session. Track failed sign-in attempts and lock expiry using an account-scoped or equivalent server-side rate-limit key, while preserving generic responses to avoid account enumeration.

3. Implement account-scoped identity-verification attempt tracking and lockout. Failed identity-code attempts must remain locked across new sessions/sign-ins until the lock period expires, and successful identity verification should reset the account-level identity failure counter.

## DECISION

FAIL