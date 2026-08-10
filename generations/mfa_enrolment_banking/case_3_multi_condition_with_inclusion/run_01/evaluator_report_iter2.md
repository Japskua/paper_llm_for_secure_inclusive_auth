## SUMMARY

The artifact is a valid single-file Bun TypeScript application with a polished mobile-oriented MFA flow, working client-side navigation, HTTPS configuration, CSP nonces, CSRF headers, encrypted OTP-seed storage, hashed recovery codes, and server-side TOTP verification. However, it does not meet all security and authorization requirements. Most importantly, any syntactically valid email can obtain the hard-coded account-owner session and modify the same shared MFA state. There are also weaknesses in OTP provisioning/replay handling, recovery-code attempt protection, secret generation, origin allow-listing, and exposure of sensitive mock values in the on-page log panel.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no framework/build tooling**
  - The full server, HTML, CSS, and browser JavaScript are contained in `app.ts`.
  - It uses `Bun.serve()` directly and does not require bundlers, external dependencies, or external assets.

- **PASS — TLS/HTTPS server configuration**
  - Bun is configured with `certs/cert.pem` and `certs/key.pem`.
  - The server advertises `https://localhost:3000`.

- **PASS — Responsive mobile MFA enrolment UI**
  - The page includes a mobile viewport meta tag, constrained content width, responsive CSS, large form controls, adequate spacing, plain-language copy, step indicators, icons, and accessible labels.
  - The enrolment sequence is implemented: sign-in → identity code → authenticator setup → authenticator confirmation → recovery-code acknowledgement → settings.

- **PASS — Manual and QR-based authenticator provisioning**
  - The authenticator setup screen provides a QR code, provisioning URI, manual secret, and copy buttons.
  - The provisioning secret can be submitted manually to an authenticator app, satisfying the manual fallback requirement.

- **PASS — Client-side mock delivery logging and deterministic test values**
  - Identity codes, authenticator test codes, and recovery codes are displayed in the browser flow and written with `console.log`.
  - The client can autofill the mock identity and authenticator codes through “Use demo code” buttons.

- **PASS — Server-side TOTP verification**
  - TOTP verification occurs on the server after decrypting the stored seed.
  - The implementation uses HMAC-SHA-1 TOTP with 30-second time steps and validates current/adjacent windows.

- **PASS — Input validation and generic server error handling**
  - Email, six-digit code, and recovery-code formats are validated server-side.
  - JSON body size is limited.
  - The top-level request handler returns a generic error rather than exposing a stack trace.

- **PASS — Secure response headers**
  - The application sets CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, and a restrictive `Permissions-Policy`.
  - The HTML response uses a per-response CSP nonce for inline style and script blocks.

- **PASS — Session cookie attributes and session expiration**
  - The session cookie is `HttpOnly`, `Secure`, `SameSite=Strict`, and has a bounded lifetime.
  - The server enforces idle and absolute session expiration.
  - Logout invalidates the server-side session and expires the cookie.

- **PASS — CSRF protection on authenticated state-changing endpoints**
  - Authenticated `POST` endpoints require both a same-origin/trusted `Origin` header and an `X-CSRF-Token` matching the session token.
  - Session cookies use `SameSite=Strict`.

- **FAIL — Broken access control / account-owner authorization**
  - `/api/signin` accepts **any valid email address** and always creates a session for `userId: "account-owner"`.
  - The global `user` MFA state is shared for every session, while `user.email` is never checked.
  - A caller can submit `attacker@example.test`, receive an account-owner session, complete the deterministic identity check, and alter the MFA configuration/recovery codes for the shared account state.
  - This violates the requirement that only the authenticated account owner may view or modify their own MFA settings and that manipulated identities must be rejected.

- **FAIL — Cryptographically secure OTP shared-secret generation**
  - The OTP seed is hard-coded as `DEMO_SEED = "JBSWY3DPEHPK3PXP"`.
  - Every provisioning operation uses the same seed instead of generating a new secret with a cryptographically secure RNG.
  - Encrypting a static seed at rest does not satisfy the requirement to generate OTP shared secrets securely.

- **FAIL — OTP single-use protection can be reset by reprovisioning**
  - `/api/authenticator/provision` executes `user.usedTotpSteps.clear()`.
  - The endpoint remains available after `user.mfaEnabled` is true.
  - A user can reprovision and reset the used-step tracking, which can permit a previously accepted TOTP time-step value to be accepted again if still within the allowed window.
  - This fails the single-use verification-code requirement.

- **FAIL — Recovery-code verification has no rate limiting or lockout**
  - `/api/recovery/verify` permits unlimited failed recovery-code attempts.
  - Identity and authenticator checks have failure counters and lockouts, but recovery verification does not.
  - The security requirements require rate limiting and lockout for repeated failed verification attempts.

- **FAIL — CORS/trusted-origin allow-list is too broad and mishandles IPv6 localhost**
  - `trustedOrigin()` accepts any HTTPS origin hosted on `localhost`, `127.0.0.1`, or `::1`, regardless of port. This is not a strict trusted-origin allow-list.
  - Any HTTPS application running on another localhost port could make credentialed cross-origin requests if it can obtain the CSRF token.
  - For standard URL parsing, IPv6 hostnames are represented as `[::1]`; the code checks for `"::1"`, so requests from `https://[::1]:3000` may be rejected despite the stated TLS support for `::1`.

- **FAIL — Sensitive values remain visible in an on-page log panel**
  - The `log()` function writes mock identity codes, authenticator codes, and recovery codes into the persistent `#logs` DOM panel.
  - Recovery codes remain readable in the page even after moving to settings, increasing exposure to shoulder-surfing and DOM inspection.
  - Browser `console.log` is explicitly required for mocks, but the persistent visible log panel is not necessary to satisfy that requirement and conflicts with the requirement not to expose OTPs or backup codes in logs.

- **FAIL — Inclusive retry/reveal/hide behavior is incomplete**
  - The setup screen permanently displays the full secret and provisioning URI without a hide/reveal control.
  - The requirements call for users to be able to reveal and hide codes/secrets and retry/re-request them without penalty.
  - The application supports re-requesting setup, but not hiding or selectively revealing sensitive setup material.

## FAILING_ITEMS

- Any valid email address can create the hard-coded `account-owner` session; email/account ownership is not enforced.
- MFA state is global (`const user`) rather than scoped to an authenticated user account.
- The OTP seed is static (`DEMO_SEED`) rather than generated with cryptographically secure randomness per enrolment.
- Reprovisioning clears `usedTotpSteps`, undermining the single-use TOTP requirement.
- Reprovisioning remains permitted after MFA is enabled without a deliberate, separately authorized reset/replacement process.
- Recovery-code verification has no failed-attempt counter, rate limit, or lockout.
- The origin policy allows arbitrary HTTPS localhost ports instead of an exact trusted-origin allow-list.
- IPv6 loopback origin handling is likely broken because URL hostname values use `[::1]`, not `::1`.
- Sensitive mock values are retained in the visible in-page logs panel.
- Setup secrets cannot be hidden after display, despite the reveal/hide requirement.

## NEW_TASKS

1. Replace the shared hard-coded account session model with a server-side account record keyed by an authenticated user identity; reject sign-in attempts for identities other than the configured mock account, or implement a mock authentication check that binds the session to the submitted account.

2. Scope MFA state, OTP seed, verification attempts, lockouts, recovery-code hashes, and MFA status to `session.userId` rather than a single global `user` object.

3. Generate a new Base32-compatible OTP shared secret with `crypto.getRandomValues()` for each authorised authenticator enrolment; retain deterministic mock verification behavior separately if required for testing.

4. Prevent accepted TOTP steps from being reset by ordinary provisioning requests; preserve used-step history, or require an explicit authenticated MFA-reset/replacement flow before replacing an existing authenticator.

5. Add per-account recovery-code failure counters, a bounded attempt window, and lockout/rate-limit responses to `/api/recovery/verify`.

6. Replace `trustedOrigin()` with an exact allow-list of supported origins, including `https://localhost:3000`, `https://127.0.0.1:3000`, and `https://[::1]:3000`; use that same allow-list for CORS and CSRF origin validation.

7. Remove the persistent visible `#logs` panel or redact sensitive values from it; retain required mock delivery values in browser `console.log` only.

8. Add hide/reveal controls for the provisioning URI and manual secret, with the secret hidden by default after initial setup display while retaining copy functionality.

## DECISION

**FAIL**