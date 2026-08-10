## SUMMARY

The artifact is a substantial single-file Bun MFA enrolment implementation with working server-side session ownership, CSRF checks, TLS, secure headers, encrypted TOTP seeds, hashed recovery codes, rate limiting, and a mobile-oriented UI. However, it does not fully meet the mock-testing deliverable because mock OTP values are logged to the browser console but are not displayed in the UI. It also only accepts `https://localhost:<port>` as an origin by default, so opening the supplied TLS-enabled app through `https://127.0.0.1:<port>` or `https://[::1]:<port>` causes all browser POST actions to be rejected.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no framework, bundler, external assets, or external network calls**
  - All server logic, HTML, CSS, and browser-side vanilla JavaScript are contained in `app.ts`.
  - The app uses `Bun.serve` directly and does not depend on external assets or APIs.

- **PASS — TLS is configured using the required certificate paths**
  - The server loads `certs/cert.pem` and `certs/key.pem` and passes them to `Bun.serve({ tls: ... })`.
  - This satisfies the requirement to use the provided mkcert certificates.

- **PASS — Mobile-responsive and dyslexia-conscious UI**
  - The HTML includes a mobile viewport meta tag and constrains the main layout to a mobile-friendly width.
  - Typography uses large sizing, increased letter spacing, adequate line height, plain wording, clear step headings, and generous padding.
  - The UI does not contain animation, flashing content, countdown timers, or reading time limits.
  - Inputs provide suitable `autocomplete`, `inputmode`, and short code-format examples.

- **PASS — Sign-in, identity verification, authenticator enrolment, recovery-code generation, and completion flow are implemented**
  - The client flow progresses through sign-in, identity-code request/verification, authenticator setup/verification, recovery-code saving/regeneration, and completion.
  - The API supports all corresponding transitions.
  - Identity codes, authenticator codes, and recovery codes are verified server-side.

- **FAIL — Mock OTP values are not returned visibly to the UI as required**
  - `/api/identity/request` returns `mockIdentityCode`, and `/api/authenticator/setup` returns `mockTotpCode` in mock mode.
  - The browser client only sends these values to `console.log`; it does not render either mock identity code or mock TOTP code in the visible UI.
  - The requirements explicitly state that testing mocks such as OTPs and backup recovery codes must be “returned to UI and shown in the console.log there.”
  - Recovery codes are displayed in the UI and logged, but the identity OTP and authenticator OTP do not meet this requirement.

- **PASS — Recovery codes are displayed, copyable, regenerable, expire, and are single-use**
  - Recovery codes are shown in the recovery screen, can be copied, can be hidden/revealed, and can be regenerated.
  - Regeneration invalidates the old stored hash set.
  - Recovery-code hashes are removed after successful use, making them single-use.
  - Expiry is enforced server-side.

- **PASS — Manual authenticator setup and QR/provisioning options are available**
  - The app provides a generated QR canvas, a provisioning URI, and a manual setup key.
  - The provisioning URI and manual key can be copied.
  - The user can manually enter the six-digit authenticator code.

- **PASS — Broken access control protections**
  - MFA API endpoints obtain the authenticated user exclusively from the server-side session cookie.
  - No user ID is accepted from the browser for MFA operations, preventing manipulated user identifiers and IDOR-style access.
  - State-changing endpoints require an anti-CSRF token.
  - Sessions use account-bound user IDs stored server-side.

- **PASS — Security headers and cookie configuration**
  - Responses include CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, and `Referrer-Policy`.
  - Session and bootstrap cookies are `Secure`, `HttpOnly`, and `SameSite=Strict`.
  - API responses use `Cache-Control: no-store, private`.

- **PASS — Secrets and verification material are protected at rest**
  - Authenticator seeds are encrypted using AES-GCM.
  - Recovery codes and identity codes are stored as SHA-256 hashes with a server-generated pepper.
  - Random production-mode tokens, seeds, and recovery codes are generated with `crypto.getRandomValues`.
  - Secrets are not persisted in `localStorage`, `sessionStorage`, or client-readable cookies.

- **PASS — Input validation and XSS protections**
  - Email, password length, six-digit OTPs, and recovery-code formats are validated server-side.
  - Browser-rendered dynamic values are escaped with a DOM-based `esc()` helper before insertion through `innerHTML`.
  - There are no user-controlled redirects or external redirect parameters.

- **PASS — Verification lifecycle, replay protection, rate limiting, and session management**
  - Identity codes have expiry and a `used` marker.
  - TOTP time steps are recorded after use to prevent replay.
  - Recovery-code hashes are deleted after use.
  - Failed attempts are rate-limited and lock the relevant operation after five failures.
  - Sessions are rotated at sign-in, have idle and absolute timeouts, and are invalidated on logout.
  - Login failures use a generic credential error message.

- **FAIL — Default origin handling breaks the app when accessed through TLS certificate-supported loopback hosts other than `localhost`**
  - `ORIGIN` defaults only to `https://localhost:${PORT}`.
  - The server rejects any request with an `Origin` header that does not exactly equal this value:
    ```ts
    if (request.headers.get("origin") && request.headers.get("origin") !== ORIGIN)
    ```
  - The supplied certificates are explicitly intended for `localhost`, `127.0.0.1`, and `::1`.
  - If the mobile browser opens `https://127.0.0.1:<port>` or `https://[::1]:<port>`, same-origin browser POST requests include that origin and are rejected with HTTP 403. Sign-in and all subsequent MFA actions fail.
  - This is a functional deployment issue, not merely a CORS preference.

## FAILING_ITEMS

- Mock identity codes are returned by the API and logged in the browser console, but they are not visibly shown in the UI in academic mock mode.
- Mock authenticator/TOTP codes are returned by the API and logged in the browser console, but they are not visibly shown in the UI in academic mock mode.
- The default origin allow-list supports only `https://localhost:<port>`, despite the intended TLS certificate hosts also including `127.0.0.1` and `::1`.
- Opening the app via `https://127.0.0.1:<port>` or `https://[::1]:<port>` prevents all state-changing browser requests, including sign-in, due to the strict origin comparison.

## NEW_TASKS

1. In academic mock mode, render the returned `mockIdentityCode` in the identity-check UI after requesting a code, while retaining the required browser `console.log`.
2. In academic mock mode, render the returned `mockTotpCode` in the authenticator setup UI after provisioning details are prepared, while retaining the required browser `console.log`.
3. Replace the single default `ORIGIN` equality check with a strict trusted-origin allow-list that supports the configured app origin and the intended local TLS origins: `https://localhost:<port>`, `https://127.0.0.1:<port>`, and `https://[::1]:<port>`.
4. Use the same trusted-origin allow-list for both request-origin rejection and CORS response headers, without allowing arbitrary origins.

## DECISION

FAIL