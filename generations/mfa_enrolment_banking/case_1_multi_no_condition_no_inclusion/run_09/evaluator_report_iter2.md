## SUMMARY

The artifact is a single-file Bun HTTPS SPA with a responsive mobile UI, simulated MFA flow, server-side session checks, CSRF checks, encrypted TOTP secret storage, hashed recovery codes, TOTP verification, recovery-code invalidation, secure headers, and browser-console mock output. However, it does not fully meet the security requirements: all successfully signed-in users are assigned the same Marcus account ID, malformed verification inputs bypass failure tracking and lockout logic, and the sign-in response incorrectly combines two `Set-Cookie` values into one header.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no framework, build tool, external assets, or compilation requirement.**  
  The entire server, HTML, CSS, and vanilla browser JavaScript are contained in `app.ts`. It uses `Bun.serve` and does not depend on external assets or network calls.

- **PASS — HTTPS/TLS is configured using the required certificate paths.**  
  The application reads `certs/cert.pem` and `certs/key.pem` and configures them in `Bun.serve({ tls: { cert, key } })`. It also rejects non-HTTPS request URLs.

- **PASS — Mobile-responsive SPA UI is provided.**  
  The page uses a mobile viewport meta tag, constrained mobile-friendly layout, readable controls, responsive code columns, and semantic forms/headings.

- **PASS — Sign-in, identity verification, authenticator setup, TOTP verification, backup-code display, confirmation, settings, recovery-code verification, regeneration, and logout flows exist.**  
  The hash routes and matching UI screens are implemented, and the corresponding API endpoints exist.

- **PASS — Internal navigation is constrained to internal routes.**  
  Client routes are limited to known hash routes, and server-side `validRedirect` uses an explicit allow-list.

- **PASS — Authenticator provisioning supports manual setup.**  
  `/api/mfa/provision` returns a manual Base32 secret, and the setup screen displays it using `textContent`. The user can submit authenticator-generated TOTP codes manually.

- **PASS — Simulated TOTP and recovery-code values are returned to the browser and logged there.**  
  The browser receives mock provisioning and recovery values, renders required UI values, and calls `console.log` through `log()`. This satisfies the explicit testing/mock-output deliverable.

- **PASS — MFA endpoints obtain identity from an HttpOnly server-side session rather than client-provided user IDs.**  
  MFA endpoints call `authorized(request)` and derive state through `session.userId`. There are no user ID parameters accepted by these endpoints.

- **FAIL — Server-side authorization does not reliably isolate account owners.**  
  Every successful sign-in creates a session with `userId: "account_marcus_001"` regardless of the submitted valid email and phone number. Therefore, any browser that obtains its own identity challenge can authenticate into the same MFA record and view or modify Marcus’s MFA configuration. This violates the requirement that only the authenticated account owner may view or modify their own MFA settings.

- **PASS — CSRF protections are present for authenticated state-changing MFA requests.**  
  MFA provisioning, OTP verification, backup-code regeneration, recovery-code use, and logout require a matching `X-CSRF-Token` and an exact allow-listed `Origin`. Session cookies also use `SameSite=Strict`.

- **PASS — Security response headers are implemented.**  
  Responses include CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, referrer policy, permissions policy, and no-store caching.

- **PASS — CORS is restricted to an explicit trusted-origin allow-list.**  
  Only `https://localhost:3000`, `https://127.0.0.1:3000`, and `https://[::1]:3000` are accepted. Other origins are rejected.

- **FAIL — Sign-in sends multiple cookies using one invalid combined `Set-Cookie` header.**  
  The sign-in endpoint uses:
  ```ts
  { "Set-Cookie": `${sessionCookie(id)}, ${expiredCookie(CHALLENGE_COOKIE_NAME)}` }
  ```
  `Set-Cookie` headers must be sent as separate header fields, not comma-concatenated. This can cause incorrect cookie parsing, including failure to expire the identity-challenge cookie and malformed `Max-Age` parsing. The server must append two independent `Set-Cookie` headers.

- **PASS — Session cookies are configured with HttpOnly, Secure, SameSite, Path, and server-side expiry checks.**  
  The session cookie uses `HttpOnly; Secure; SameSite=Strict; Path=/`. Server-side checks enforce idle and absolute expiration, and sessions are removed on logout.

- **PASS — Session fixation mitigation is implemented.**  
  On sign-in, any prior session ID is deleted and a new cryptographically random session ID is created.

- **PASS — TOTP secrets are generated with a CSPRNG and encrypted at rest.**  
  Secrets are generated with `crypto.getRandomValues`, stored using AES-GCM, and decrypted only for verification.

- **PASS — Recovery codes are generated securely and stored as salted PBKDF2 hashes.**  
  Recovery codes use CSPRNG Base32 data and are stored as PBKDF2-SHA-256 hashes with unique salts. Raw recovery values are not retained server-side after the response.

- **PASS — OTP verification is time-bound and protected against reuse during enrolment.**  
  Provisioning expires after five minutes. TOTP validation uses a 30-second RFC-compatible counter with limited clock skew and records the accepted counter to prevent repeated enrolment consumption.

- **FAIL — Repeated malformed verification attempts do not contribute to rate limiting or lockout.**  
  Invalid OTP format, invalid recovery-code format, and invalid identity-code format return immediately before `recordFailure()` is called. An attacker can submit unlimited malformed attempts without incrementing failure counters. The requirement calls for rate limiting and lockout of repeated failed verification attempts; malformed attempts must be counted or separately rate-limited.

- **PASS — Valid failed verification attempts are rate-limited and locked.**  
  Valid-format but incorrect identity codes, OTPs, and recovery codes increment attempt state and can trigger a lockout.

- **PASS — Recovery codes are single-use.**  
  Successful recovery-code verification marks the matched stored code as `used: true`, and the code cannot be used again.

- **PASS — Input validation and output handling are generally safe.**  
  Email, phone, OTP, and recovery code formats are validated server-side. User-controlled values are not injected into HTML templates; dynamic display uses `textContent` or DOM element creation.

- **PASS — Generic errors and no verbose stack traces are returned.**  
  The request handler catches errors and returns a generic JSON failure message without stack traces or debug data.

## FAILING_ITEMS

- All authenticated sessions are assigned the fixed user ID `account_marcus_001`. Any party who completes the mock challenge with any valid email and phone can operate on the same MFA record. This fails account-owner isolation and authorization requirements.

- The sign-in response concatenates session creation and challenge-cookie deletion into one `Set-Cookie` header. Cookies must be emitted as separate `Set-Cookie` header fields.

- Invalid-format identity codes, OTPs, and recovery codes bypass the failure counters. This permits unlimited malformed verification attempts without lockout or rate limiting.

## NEW_TASKS

1. Replace the fixed `userId: "account_marcus_001"` sign-in assignment with a server-side account identity model that maps the authenticated mock identity to an account-specific user ID; ensure distinct authenticated identities cannot read or modify the same `MfaRecord`.

2. Update the sign-in response to append separate `Set-Cookie` headers for the new session cookie and identity-challenge-cookie expiration, rather than joining them with a comma.

3. Apply verification attempt accounting or endpoint-level rate limiting to malformed identity-code, TOTP, and recovery-code submissions before returning validation failures.

## DECISION

FAIL