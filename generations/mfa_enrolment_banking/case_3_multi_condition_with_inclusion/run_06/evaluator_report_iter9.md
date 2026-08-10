## SUMMARY

The artifact is a well-structured single-file Bun application with strong coverage of session security, CSRF, TLS, security headers, encrypted TOTP secrets, hashed recovery codes, rate limiting, and a mobile-oriented accessible UI. However, the normal/default enrolment flow is not usable end-to-end: there is no normal sign-in route, and the simulated identity-verification code is neither delivered nor exposed to the browser in non-test mode. This prevents a user from completing MFA enrolment without special server configuration or manually supplied authenticated headers.

## FUNCTIONAL_CHECK

- **PASS — Single-file, zero-compilation implementation**
  - The complete Bun server, HTML template, CSS, and browser-side vanilla JavaScript are contained in one `app.ts`.
  - No framework, bundler, compiler, external assets, or external network calls are used.

- **PASS — TLS server configuration**
  - `Bun.serve` is configured with `tls: { cert: "certs/cert.pem", key: "certs/key.pem" }`.
  - The server only advertises an HTTPS URL.

- **PASS — Mobile and dyslexia-conscious UI**
  - The page uses a constrained mobile-width layout (`width:min(100%,560px)`), readable font sizing, letter/line spacing, large controls, focus indicators, short instructions, plain language, icons, examples, help text, and predictable four-step progression.
  - The UI has no animation, flashing content, countdowns, or reading time limits.

- **PASS — Authenticator provisioning and manual setup support**
  - The application creates a QR code and displays/copies the corresponding setup secret.
  - The secret is available for manual entry into an authenticator app.
  - The OTP verification form supports manual six-digit code entry.

- **PASS — Backup-code generation and storage flow**
  - Eight recovery codes are generated, displayed on demand, and can be copied.
  - The user cannot finish enrolment before authenticator verification and recovery-code generation.
  - Recovery codes are stored server-side as salted `scrypt` hashes and are consumed on successful `/api/recovery/verify`.

- **PASS — TOTP and recovery verification controls**
  - TOTP is calculated server-side using HMAC-SHA1 over Base32-decoded secrets.
  - TOTP verification accepts a bounded time window and rejects reuse of the accepted TOTP counter.
  - Identity codes are single-use and expire.
  - Recovery codes are single-use because matched hashes are removed after successful verification.

- **PASS — Server-side authorization / IDOR protections**
  - MFA records are looked up exclusively by the authenticated session account ID.
  - Client input never selects an account/user ID.
  - Every protected MFA API route calls `requireOwner`.
  - Guessed or manipulated user identifiers cannot be used to access another account because no user identifier is accepted by these endpoints.

- **PASS — CSRF protections**
  - State-changing protected requests require both a trusted `Origin` and a session-bound `X-CSRF-Token`.
  - Session cookies use `SameSite=Strict`.
  - Login/test-login endpoints require a trusted same-origin request before issuing a session.

- **PASS — Secure cookie and HTTP response configuration**
  - Session cookies include `HttpOnly`, `Secure`, `SameSite=Strict`, and `Path=/`.
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, and `Cache-Control: no-store` are present.
  - CSP uses a per-page nonce for inline script and style content.
  - CORS preflight requests are restricted to the stated localhost HTTPS origins.

- **PASS — Secret handling at rest and browser storage**
  - TOTP seeds are encrypted using AES-256-GCM before being placed in the account record.
  - Recovery codes are salted and hashed with `scrypt`.
  - Sensitive values are not put in URLs, localStorage, sessionStorage, or non-HttpOnly cookies.
  - Server logging does not log secrets, OTPs, backup codes, or session tokens.

- **PASS — Input validation and output encoding**
  - Phone suffixes, OTPs, fixture text, and recovery-code formats are validated server-side.
  - UI messages and values that are inserted with `innerHTML` are escaped through `esc`.
  - There is no database layer or dynamic SQL, so there are no non-parameterized SQL queries.

- **PASS — Failed-attempt handling and session lifecycle**
  - Failed code entries are counted and locked after five failures for five minutes.
  - Successful verification clears failures.
  - Identity verification rotates the session identifier.
  - Idle and absolute session timeouts are checked server-side.
  - Logout invalidates the server session and clears the cookie.

- **FAIL — Default MFA enrolment is not completable**
  - In normal mode, `/api/identity/send` generates a random identity code but returns only `{ ok: true }`.
  - The browser logs only `"Simulated identity code delivery sent."`; it does not log or display the actual code.
  - There is no SMS/email delivery implementation, which is acceptable only if the mock value is made available as required. As written, the user cannot know the code needed by `/api/identity/verify`.
  - The flow is only completable when `MFA_TEST_MODE=1` and the special academic fixture login is used.

- **FAIL — The default application has no usable authentication entry point**
  - When opened normally, the app shows “Sign in through SafeBank before opening MFA setup,” but provides no normal sign-in action or usable simulation.
  - The only non-test production path requires an externally generated HMAC assertion in request headers (`x-preauthenticated-*`), which a normal browser user cannot provide.
  - This may be an acceptable upstream-authentication integration boundary in a real deployment, but it does not satisfy the delivered standalone academic SPA flow without external setup.

- **FAIL — Simulated delivery values are not consistently returned/logged in the browser**
  - The requirements specifically require mock OTP and recovery values to be returned to the UI and shown through browser `console.log` for testing.
  - In ordinary mode, the identity OTP is neither returned to UI nor logged to the browser console.
  - In ordinary mode, backup codes are returned to the UI but only a generic message is logged; their values are logged only in test mode.
  - The “Get a new test code” button is shown in normal mode, but `/api/totp/test` returns no code outside fixture mode, making that visible action ineffective.

## FAILING_ITEMS

- The normal identity-verification mock generates a random code that is inaccessible to the user. This blocks all subsequent MFA enrolment steps outside academic fixture mode.
- The default UI does not provide a usable sign-in or standalone mock-authentication route. It depends on a privileged upstream signed assertion that cannot be supplied by a regular browser user.
- Mock secret/code output does not consistently meet the requirement to return testing values to the UI and log them in the browser console.
- The normal-mode “Get a new test code” control is misleading because the endpoint returns `{ ok: true }` without a code, and the UI gives no useful outcome.

## NEW_TASKS

1. Implement a complete, explicitly labelled standalone mock-authentication path for the academic app, or make the existing academic fixture sign-in available through a documented default development configuration so the app can be used without externally injected HMAC headers.

2. Make simulated identity-code delivery functional in every supported standalone mode:
   - Return the generated mock identity OTP in the API response.
   - Display it in the intended test/mock UI when appropriate.
   - Log the exact mock code with `console.log` in the browser.
   - Keep this behavior clearly marked as simulation/test behavior and do not enable it in a real production configuration.

3. Align browser-side test-code behavior across the flow:
   - Return and browser-log backup recovery-code values where the requirements require test output.
   - Either return/log an actual current TOTP for the normal mock mode or hide/disable the “Get a new test code” button outside modes where a code can be provided.
   - Ensure every visible test/re-send control gives a clear confirmation and a usable result.

## DECISION

FAIL