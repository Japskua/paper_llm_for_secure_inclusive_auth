## SUMMARY

The artifact is structured as a single Bun-served `app.ts` with in-memory MFA state, TLS configuration, security headers, session handling, CSRF protection, encrypted TOTP seeds, hashed recovery codes, and a mobile-oriented UI. However, the browser JavaScript embedded in the generated HTML contains a syntax error in the QR-code function. This prevents the entire client application from loading or functioning, leaving the page at “Loading…”. Therefore, the artifact cannot be accepted despite several sound server-side security measures.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no external assets/build tooling**
  - The server, HTML, CSS, and browser JavaScript are all in `app.ts`.
  - It uses Bun directly and only Node/Bun built-ins. TLS certificate files are local required inputs, not external network assets.

- **PASS — TLS server configuration and secure session-cookie attributes**
  - `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`.
  - Session cookies include `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, and a bounded `Max-Age`.

- **PASS — Server-side authorization and session ownership**
  - Protected MFA routes derive the account exclusively from the authenticated server-side session via `owner(request)`.
  - Client-provided account/user IDs are not accepted, substantially preventing IDOR-style account manipulation.
  - The session identifier is regenerated after successful identity verification.

- **PASS — CSRF controls on state-changing operations**
  - Sign-in initiation, sign-in verification, MFA enrollment, MFA confirmation, recovery-code generation, recovery-code verification, and logout require an `X-CSRF-Token`.
  - Same-origin/trusted-origin checks are also applied through `trusted(request)`.

- **PASS — Security headers, restrictive CORS, generic server errors**
  - Responses set CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, and `Permissions-Policy`.
  - CORS is only emitted for recognized local HTTPS origins.
  - The top-level handler returns a generic error response rather than a stack trace.

- **PASS — Secure storage and generation of MFA material**
  - TOTP secrets are stored server-side with AES-256-GCM encryption.
  - Backup recovery codes are generated with cryptographic randomness and stored as PBKDF2-derived hashes with a server-side pepper.
  - Session values and secrets are not written to `localStorage`, `sessionStorage`, or non-HttpOnly cookies.

- **PASS — OTP/recovery verification properties on the server**
  - Identity codes have a short expiry and are marked used after successful verification.
  - TOTP values are checked against adjacent time windows and used TOTP time steps are tracked to prevent reuse.
  - Recovery codes are one-time, expiration-bound, and marked used after success.
  - Failed identity, authenticator, and recovery-code attempts are rate-limited/locked out.

- **FAIL — Browser UI loads and all enrolment interactions work**
  - The browser script has a syntax error in `qr(payload)`:
    ```js
    m[row][cc]!!v;
    ```
  - This is invalid JavaScript. It appears to be intended as:
    ```js
    m[row][cc] = !!v;
    ```
  - Because parsing fails before any client code runs, the initial page never progresses beyond `Loading…`, and no API calls, sign-in flow, MFA setup, recovery-code flow, clipboard actions, or browser console mock logs can work.

- **FAIL — QR-code option is functional**
  - Even after correcting the JavaScript syntax error, the QR renderer sets:
    ```js
    box.style.gridTemplateColumns = "repeat(" + size + ",1fr)";
    ```
  - The page CSP uses a nonce-only `style-src` and does not permit style attributes. Dynamically setting an inline `style` attribute is blocked by this policy in CSP-enforcing browsers.
  - As a result, the QR grid layout may not render as an actual square QR matrix. The fixed 57-column layout should be defined in the nonce-bearing stylesheet instead.

- **FAIL — Accessible, mobile MFA flow is actually delivered to the user**
  - The authored UI has several positive accessibility-oriented design choices, including plain language, spacing, examples, large controls, icon/text branding, and copy controls.
  - However, none of those screens are reachable because the browser script fails to parse. The functional UX requirement is therefore not met.

- **FAIL — One clear primary action per screen**
  - In the recovery-code replacement confirmation state, the existing “I saved my codes” primary button remains visible while `replacementPrompt()` adds another primary button, “Yes, replace all codes.”
  - This creates two simultaneous `.primary` actions on one screen, conflicting with the requirement to present one clear primary action per screen.

## FAILING_ITEMS

- The embedded browser JavaScript has an unrecoverable syntax error in the QR encoder:
  ```js
  m[row][cc]!!v;
  ```
  This stops all client-side JavaScript execution.

- The QR layout depends on a JavaScript-generated inline style attribute that conflicts with the nonce-only CSP:
  ```js
  box.style.gridTemplateColumns = "repeat(" + size + ",1fr)";
  ```
  This can prevent the QR matrix from rendering correctly under the application’s own security policy.

- The recovery-code replacement confirmation state presents more than one primary action at once:
  - “I saved my codes”
  - “Yes, replace all codes”

- Because the client script does not load, the required operational behaviours are unavailable:
  - mock values are not logged in the browser console;
  - sign-in and identity verification cannot occur;
  - authenticator setup and verification cannot occur;
  - recovery-code creation/copying/verification cannot occur;
  - navigation between screens cannot occur.

## NEW_TASKS

1. Correct the QR encoder syntax error by replacing:
   ```js
   m[row][cc]!!v;
   ```
   with:
   ```js
   m[row][cc] = !!v;
   ```

2. Make the QR grid compatible with the configured CSP by defining the fixed Version-10 grid columns in the nonce-bearing CSS, for example:
   ```css
   .qr { grid-template-columns: repeat(57, 1fr); }
   ```
   Then remove the runtime `box.style.gridTemplateColumns` assignment.

3. Update the recovery-code confirmation rendering so that only the replacement decision is the primary action while confirmation is displayed; hide or demote “I saved my codes” until the replacement prompt is dismissed.

4. Run the Bun server with valid local TLS certificates and manually verify the complete browser flow: initial session creation, sign-in code delivery and verification, QR/manual authenticator setup, TOTP confirmation, recovery-code creation/copying, recovery-code single-use verification, regeneration, logout, and browser-console mock logging.

## DECISION

**FAIL**