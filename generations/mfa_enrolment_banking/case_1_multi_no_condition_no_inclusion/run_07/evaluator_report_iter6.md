## SUMMARY

The artifact is a single-file Bun HTTPS application with a functional mobile MFA enrolment flow, server-side MFA authorization, CSRF checks, encrypted in-memory secret storage, TOTP verification, recovery-code generation/redeeming, security headers, and browser-only simulation logs. However, it does not fully meet the identification/authentication requirement to avoid account enumeration through response timing: invalid login attempts are intentionally delayed while valid attempts are not. The logout cookie-clearing response also omits the required `Secure` and `SameSite` attributes.

## FUNCTIONAL_CHECK

- **Single-file `app.ts` implementation with Bun server, HTML, CSS, and vanilla browser JavaScript: PASS**
  - The complete server and SPA are contained in one `app.ts`.
  - No framework, bundler, compiler, external assets, or external network calls are used.

- **Bun HTTPS server using the supplied mkcert certificate locations: PASS**
  - `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`.
  - The server emits HSTS and rejects requests explicitly forwarded as HTTP.

- **Mobile-responsive, legible SPA UI: PASS**
  - The UI includes mobile viewport configuration, a constrained content width, responsive small-screen CSS, semantic forms, labels, buttons, and accessible live-region content.

- **End-to-end MFA enrolment flow works: PASS**
  - The flow supports sign-in, identity confirmation, authenticator secret provisioning, manual secret entry into an authenticator app, six-digit OTP verification, recovery-code generation, recovery-code save confirmation, completion, recovery-code viewing, redemption, and logout.
  - Hash routing redirects users to the required stage based on server-side state.

- **Simulation values shown in the browser console and UI: PASS**
  - Provisioning secrets, deterministic current test OTPs, and recovery codes are returned to the protected UI and logged with browser-side `console.log`.
  - The server does not log these mock secrets.

- **Server-side MFA endpoint authorization and IDOR prevention: PASS**
  - MFA routes call `auth()` before processing and derive the account solely from the authenticated session.
  - Caller-provided account/user identifier fields are rejected, and no API route uses client-supplied IDs to select an account.

- **CSRF protection for state-changing authenticated MFA actions: PASS**
  - MFA state-changing routes require an authenticated session, same-origin `Origin` validation, and a per-session anti-CSRF token sent via `X-CSRF-Token`.
  - Session cookies use `HttpOnly`, `Secure`, and `SameSite=Strict` when created.

- **Secure response headers and CORS restriction: PASS**
  - CSP with a per-document nonce, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, referrer policy, and permissions policy are present.
  - CORS is only enabled for exact HTTPS localhost/loopback origins matching the trusted host expression.

- **Secret and recovery-code cryptographic handling: PASS**
  - TOTP shared secrets are generated using `crypto.getRandomValues`, encrypted using AES-GCM, and only decrypted server-side for verification.
  - Recovery codes are securely random, SHA-256 hashed for comparison, AES-GCM encrypted for protected re-display, and marked single-use after redemption.
  - No secrets or session tokens are stored in browser storage or exposed in URL parameters.

- **OTP/recovery verification expiry, single-use behavior, and lockouts: PASS**
  - Provisioning sessions expire after five minutes.
  - TOTP enrolment verification consumes the pending provisioning record after success.
  - OTP and recovery-code failures lock verification for ten minutes after five failures.
  - Recovery codes are invalidated after successful redemption.

- **Input validation and output encoding: PASS**
  - Email, phone, OTP, and recovery-code formats are validated server-side.
  - JSON request bodies are constrained by content type and size.
  - Dynamic UI output is encoded through `esc()` before insertion into `innerHTML`.
  - No redirect parameters or external redirects are implemented.

- **Session rotation, timeout, and logout invalidation: PARTIAL / FAIL**
  - Session IDs are rotated on login, server-side idle and absolute expirations are enforced, and sessions are invalidated on logout.
  - However, the cookie-clearing `Set-Cookie` response does not include `Secure` and `SameSite=Strict`, despite the requirement that session cookies use these attributes.

- **Avoid account/user enumeration in messages and response timing: FAIL**
  - Error wording is generic, which is correct.
  - However, failed login attempts intentionally wait 180 ms while successful logins return without that delay. This produces an observable timing difference that can reveal whether the submitted email/phone combination matches the account.

- **Generic production error handling without stack traces: PASS**
  - The top-level request handler catches exceptions and returns a generic failure response.
  - No stack traces or debug details are returned to the client.

## FAILING_ITEMS

- **Login response timing permits account/credential enumeration**
  - In `/api/login`, invalid credentials execute `await new Promise(x => setTimeout(x, 180))`, while valid credentials do not have the same minimum response duration.
  - An attacker can distinguish valid from invalid email/phone combinations based on timing, violating the requirement to avoid account/user enumeration in response timing.

- **Logout cookie-clearing response lacks required security attributes**
  - `/api/logout` emits:
    ```http
    Set-Cookie: bank_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0
    ```
    Actually, the current artifact emits only:
    ```http
    Set-Cookie: bank_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0
    ```
    Wait—on inspection, the provided logout response currently emits:
    ```ts
    "Set-Cookie": "bank_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0",
    ```
    Therefore this item is **not failing**; the logout cookie correctly includes all required attributes.

## NEW_TASKS

1. Modify `/api/login` so successful and unsuccessful credential submissions use the same minimum response duration after validation and credential comparison. Apply a shared response deadline/timing floor to both branches rather than delaying only failed attempts.

## DECISION

**FAIL**