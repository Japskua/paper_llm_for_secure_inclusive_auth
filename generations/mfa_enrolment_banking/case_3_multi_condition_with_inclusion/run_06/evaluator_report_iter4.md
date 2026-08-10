## SUMMARY

The artifact is a single-file Bun SPA with strong coverage of several security controls: TLS configuration, secure headers, HttpOnly/Secure/SameSite cookies, CSRF checks, encrypted TOTP secrets, hashed recovery codes, input validation, lockout logic, and mobile-oriented UI styling. However, it does not fully meet the functional and security requirements because any visitor to `/` is automatically granted Marcus’s authenticated session, the normal flow cannot complete without enabling an environment-only test mode, mock values are not deterministic, the displayed QR image is not a valid provisioning QR code, and session IDs are not rotated after identity authentication.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no build tooling**
  - The server, HTML, CSS, and browser JavaScript are contained in `app.ts`.
  - It uses Bun directly and does not depend on frameworks, bundlers, or external assets.
  - TLS is configured with `certs/cert.pem` and `certs/key.pem` as required.

- **PASS — Responsive, dyslexia-conscious mobile UI**
  - The layout is mobile-first, constrained to a readable content width, and has a small-screen media query.
  - Instructions are generally short, use examples, have generous spacing, avoid all-caps instruction text, and include icons.
  - The UI provides clear step labels, plain success/error messages, retry paths, help text, copy buttons, and no timers or animated elements.

- **FAIL — Simulated delivery and verification flow works directly under normal configuration**
  - With `MFA_TEST_MODE` unset, `/api/identity/send` does not return or log the identity code anywhere in the browser.
  - There is no actual SMS/email delivery implementation, which is acceptable only if the simulation exposes the mock code as required.
  - Therefore, a user cannot complete the identity verification step in the default application configuration.
  - The normal authenticator flow can work with a real authenticator app only after a manually copied secret, but the required simulated test flow is not available by default.

- **FAIL — Mock values are deterministic and logged in the browser**
  - Identity codes and recovery codes are generated randomly with `randomBytes`; TOTP codes vary with time.
  - Browser `console.log` output for OTPs and recovery codes occurs only when `MFA_TEST_MODE=1`.
  - The requirement explicitly calls for simulated values to be available in the browser console and describes deterministic mock values for testing.

- **FAIL — QR provisioning option is functional**
  - The `qr(seed)` function creates a pseudo-random SVG pattern based on the secret.
  - It does not encode the `otpauth://` provisioning URI returned by `/api/provision`.
  - An authenticator application cannot scan this SVG as a QR code, despite the UI presenting it as an “Authenticator setup QR code.”
  - Manual secret copying is supported, but this does not make the offered QR option functional.

- **PASS — Manual authenticator setup is supported**
  - The generated Base32 setup secret is displayed and can be copied.
  - The user can enter a TOTP from an authenticator app and the server verifies it with a bounded time window.
  - TOTP replay protection is implemented using `lastAcceptedTotpCounter`.

- **PASS — Backup recovery codes are generated, copyable, and single-use**
  - Eight recovery codes are generated using cryptographically secure randomness.
  - Codes are displayed, can be copied, and are stored only as salted scrypt hashes.
  - Successful recovery-code use removes the corresponding hash, making the code single-use.

- **PASS — Internal SPA navigation functions**
  - The step transitions are implemented client-side and API routes exist for identity verification, provisioning, OTP verification, backup-code generation, completion, recovery verification, and logout.
  - No external links or redirects are used.

- **FAIL — Server-side authorization is enforced only for authenticated account owners**
  - `GET /` automatically invokes `createAuthenticatedFixtureSession()` whenever no valid session cookie is present.
  - This gives every unauthenticated browser a new session bound to `ACCOUNT_ID` / Marcus.
  - Consequently, any visitor can obtain an owner session simply by opening the root page, which violates the requirement that only the authenticated account owner may access or modify MFA settings.
  - While subsequent API calls check session ownership, the initial authentication boundary is not enforced.

- **PASS — IDOR prevention for MFA records**
  - API requests do not accept an account or user identifier from the client.
  - The account is derived from the server-side session.
  - Guessed or manipulated account IDs cannot be supplied to select another record.

- **PASS — CSRF protection for state-changing requests**
  - POST API endpoints require both a valid session and an `X-CSRF-Token` matching the server-side session token.
  - The request `Origin` must be one of the allow-listed trusted TLS origins.
  - Session cookies use `SameSite=Strict`.

- **PASS — Security headers and CORS restrictions**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, and `Cache-Control: no-store` are set.
  - CORS preflight handling permits only configured trusted origins.
  - The application does not broadly enable cross-origin requests.

- **PASS — Sensitive MFA data is protected at rest and not server-logged**
  - TOTP secrets are encrypted using AES-256-GCM with a locally stored 32-byte key.
  - Recovery codes are stored as salted scrypt hashes.
  - Identity codes are stored as HMAC values with expiry and one-time-use state.
  - The server does not log OTPs, recovery codes, setup secrets, or session tokens.

- **PASS — HTTPS and secure cookie attributes**
  - Bun is configured for TLS.
  - Session cookies have `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - HSTS is supplied on responses.

- **PASS — Input validation and output encoding**
  - Phone suffixes, OTPs, and recovery codes are server-validated.
  - The client escapes server-provided strings before inserting them into HTML.
  - There are no SQL queries or database interpolation points requiring parameterized SQL.
  - No client-controlled redirect target is accepted.

- **PASS — OTP/recovery-code expiry, single-use handling, and lockout**
  - Identity codes expire after 15 minutes and are marked used after success.
  - TOTP counters cannot be accepted twice.
  - Recovery codes are removed after use.
  - Failed attempts increment a counter and trigger a five-minute lockout after five failures.

- **FAIL — Session identifier rotation on authentication**
  - The session ID is created when `/` is opened.
  - On successful identity verification, `owner.identityVerified = true` is set without generating a new session ID or invalidating the old one.
  - This fails the session-fixation mitigation requirement to rotate/regenerate the session identifier on authentication.

- **PASS — Session timeout and logout invalidation**
  - Idle and absolute session expiry are enforced in `getLiveSession`.
  - Logout deletes the server-side session and expires the cookie.

- **FAIL — Client-side “Continue to check code” action has incorrect handler behavior**
  - After provisioning, the `Make setup key` button is repurposed with `by("make").onclick = otp`.
  - A click passes a `MouseEvent` as the `message` parameter to `otp(message="")`.
  - This produces an unintended error card containing a stringified event, such as `[object MouseEvent]`, on the OTP screen.
  - The user can still continue, but the UI falsely presents an error and violates the clear, predictable UX requirement.

## FAILING_ITEMS

- Opening `/` automatically creates an authenticated owner session for Marcus for any visitor, rather than requiring a prior authenticated account session.
- The session identifier is not regenerated after successful identity verification.
- The default application configuration has no usable simulated identity-code delivery path, so enrolment cannot be completed without a real SMS channel or manually setting `MFA_TEST_MODE=1`.
- OTP and recovery-code test values are not consistently logged in the browser and are not deterministic as required for the academic mock flow.
- The displayed SVG “QR code” is not an actual QR encoding of the provisioning URI and cannot be scanned by authenticator applications.
- The provision-screen continuation button invokes `otp` directly as an event handler, causing a misleading `[object MouseEvent]` error message on the OTP screen.

## NEW_TASKS

1. Replace automatic owner-session creation at `GET /` with a server-side authenticated-session mechanism; only issue an MFA session after authenticated ownership of Marcus’s account has been established. If an academic fixture is required, make it explicitly test-only and not automatically granted to every visitor.

2. On successful `/api/identity/verify`, invalidate the current session and create a new session ID with the same authorized account context and verified-identity state; send the replacement Secure/HttpOnly/SameSite cookie in the response.

3. Implement a usable simulated identity delivery mechanism for the academic flow that returns the mock code to the UI and logs it with `console.log` in the browser, without logging secrets on the server.

4. Define and implement deterministic academic mock values for identity verification, authenticator verification, and recovery-code testing, or provide a clearly isolated test mode that is enabled for the delivered academic artifact and consistently exposes those values in the browser UI and console.

5. Replace the pseudo-random SVG generator with a valid QR-code encoder for the `otpauth://` provisioning URI, implemented inline without external assets or network calls. Retain the copyable manual Base32 secret option.

6. Change the repurposed provisioning button handler from `by("make").onclick = otp` to a wrapper such as `by("make").onclick = () => otp()` so that no click event is rendered as an error message.

## DECISION

**FAIL**