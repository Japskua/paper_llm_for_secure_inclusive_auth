## SUMMARY

The server-side implementation covers many requested security controls and keeps the application in a single `app.ts` file with Bun TLS configuration. However, the browser client contains a fatal JavaScript syntax error in `qrSvg()`: `path` is declared twice in the same scope. Because the entire inline client script cannot parse, the SPA never boots and remains on “Loading securely…”. This prevents all enrolment, verification, recovery-code, and accessibility flows from functioning. The artifact therefore cannot be accepted.

## FUNCTIONAL_CHECK

- **Single-file Bun application with HTTPS/TLS certificates — PASS**
  - The server, HTML, CSS, and browser JavaScript are all in `app.ts`.
  - `Bun.serve()` uses `certs/cert.pem` and `certs/key.pem` and serves on HTTPS port 3000.
  - No framework, external asset, build tool, or external network request is used.

- **SPA renders and browser interactivity works directly when served — FAIL**
  - The inline browser script has a fatal duplicate declaration inside `qrSvg()`:
    - `let path="";`
    - later, `const path=document.createElementNS(...)`
  - Redeclaring `path` in the same function scope is a JavaScript syntax error. The complete inline script fails to parse, so `boot()` never runs and the UI remains at “Loading securely…”.

- **Sign-in and identity-verification flow works — FAIL**
  - The server endpoints and client flow are present, including deterministic identity code `246810`.
  - However, the client JavaScript parse failure prevents the sign-in screen and identity screen from being rendered or used.

- **Authenticator provisioning supports QR and manual secret entry/copying — FAIL**
  - The intended UI includes a QR generator, visible manual secret, copy controls, and a setup URI.
  - The fatal syntax error is inside the QR function and prevents all client UI code from executing. No provisioning options can be displayed.

- **Authenticator OTP verification is simulated, deterministic, time-bound, single-use, and rate-limited — FAIL**
  - Server-side logic correctly calculates TOTP-style six-digit codes, accepts current/previous periods, tracks used slots, and locks after repeated failures.
  - The browser cannot call the verification endpoint because the client script does not load.

- **Backup recovery codes are generated, displayed, copied, verified once, and regenerated — FAIL**
  - Server-side recovery codes use `crypto.getRandomValues`, per-code salts, PBKDF2 hashes, one-time-use tracking, and failure lockout.
  - The intended UI and browser console logging cannot run due to the client parse error.

- **Dyslexia-friendly, mobile-responsive UX — FAIL**
  - The CSS and intended component structure show substantial effort toward legible typography, spacing, plain wording, examples, icons, copy buttons, visible help, and responsive mobile layout.
  - Since the UI does not render beyond its loading text, these UX requirements are not actually delivered to the user.

- **Server-side authorization / IDOR protection — PASS**
  - Protected endpoints derive the authenticated user from the HttpOnly session cookie rather than accepting a user ID from request input.
  - `auth()` verifies session ownership against the account ID before exposing or modifying MFA state.

- **CSRF protection for state-changing operations — PASS**
  - State-changing endpoints require both a trusted `Origin` and the session-bound `X-CSRF-Token`.
  - Session cookies use `SameSite=Strict`, providing additional CSRF mitigation.

- **Security headers, CORS, cookies, and clickjacking protection — PASS**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, and `Cache-Control: no-store` are set.
  - CORS is limited to the declared local HTTPS origins.
  - Session cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`.

- **Secret handling and cryptographic storage — PASS**
  - OTP secrets are generated with `crypto.getRandomValues` and encrypted at rest with AES-GCM.
  - Recovery codes are generated with cryptographically secure randomness and stored as salted PBKDF2 hashes.
  - No secrets or session tokens are stored in browser storage or client-readable cookies.
  - The test-only secret/OTP/recovery-code presentation and browser `console.log` behavior is explicitly required by the deliverables.

- **Input validation, output safety, and redirect safety — PASS**
  - Request JSON is constrained to object input, strings are length-limited, and email/code formats are validated.
  - The UI uses DOM APIs and `textContent` rather than interpolating untrusted API values as HTML.
  - No redirect parameter or external redirect mechanism exists.

- **Session handling, generic errors, and attempt lockout — PASS**
  - New random session IDs are created on successful authentication.
  - Idle and absolute session expiry are enforced.
  - Logout invalidates the server-side session and clears the cookie.
  - Identity, OTP, and recovery-code attempts have lockout behavior.
  - Route errors are caught and returned as generic responses rather than exposing stack traces.

## FAILING_ITEMS

- The inline client script has a fatal syntax error in `qrSvg()` because `path` is declared twice in the same function scope.
- The duplicate declaration prevents the complete client script from parsing and running.
- As a result, the SPA does not boot, sign-in cannot be accessed, and no MFA enrolment or backup-code functionality works in the browser.
- The QR SVG construction code also contains unnecessary and inconsistent intermediate elements (`title`, a first unused `path`, `window.__qrPath`, and `arguments[0]` usage). Even after resolving the duplicate identifier, this code should be simplified and validated to ensure the generated QR SVG is correct.

## NEW_TASKS

1. In `qrSvg()`, rename or remove the second `const path=document.createElementNS(...)` declaration so it does not conflict with the existing QR path-data variable.
2. Simplify `qrSvg()` to create one SVG `<path>` whose `d` attribute is set to the generated QR path-data string; remove unused `title`/path creation, `window.__qrPath`, and `arguments[0]` code.
3. Load the application in a browser and verify that there are no JavaScript syntax or runtime errors in the browser console.
4. Verify the complete end-to-end flow in the browser: sign in, identity code verification, provisioning display, QR/manual-secret copy controls, OTP verification, backup-code display/copy, recovery-code one-time use, regeneration, and logout.

## DECISION

FAIL