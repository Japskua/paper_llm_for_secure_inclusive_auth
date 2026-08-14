## SUMMARY

The artifact is a single-file Bun HTTPS SPA with substantial security controls: session rotation, CSRF validation, owner-bound authenticated state, CSP/HSTS/clickjacking headers, encrypted TOTP draft storage, hashed recovery codes, input validation, and concurrency protections. However, it does not fully meet the requirements because sensitive MFA material is written to browser logs, malformed recovery-code verification attempts do not participate in lockout handling, and the customer-facing UI does not display the authenticator setup key or recovery codes needed to complete and retain the enrolment.

## FUNCTIONAL_CHECK

- **Server-side authorization and IDOR prevention — PASS**
  - MFA provisioning, confirmation, recovery verification, and regeneration require an authenticated session whose owner is the fixed mock account (`marcus-account-001`).
  - User/account identifier fields in request bodies are explicitly rejected by `manipulated()`.
  - No endpoint accepts a client-selected target user ID.

- **CSRF protection for state-changing requests — PASS**
  - All POST API calls require a valid per-session CSRF token.
  - The session cookie is also `SameSite=Strict`.

- **Secure response headers and clickjacking protections — PASS**
  - Responses include CSP with a per-response nonce, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and CSP `frame-ancestors 'none'`.
  - API responses are marked `Cache-Control: no-store`.

- **Secure cookies, generic errors, and restricted CORS — PASS**
  - Session cookies are `HttpOnly`, `Secure`, `SameSite=Strict`, use the `__Host-` prefix, and have no Domain attribute.
  - Errors are generic and do not return stack traces.
  - CORS only returns `Access-Control-Allow-Origin` for configured local HTTPS origins.

- **No exposure of OTP seeds, OTPs, recovery codes, or session tokens in logs — FAIL**
  - The browser script logs identity codes, authenticator seeds, TOTP values, initial recovery codes, and regenerated recovery codes using `console.log`.
  - This directly conflicts with Security Requirement 2, even though the final testing instruction also requests browser-console mock output. The requirements are internally conflicting; the artifact follows the testing instruction but violates the stated no-secrets-in-logs security requirement.

- **Cryptographically secure generation and protection at rest — PASS**
  - TOTP secrets, sessions, CSRF tokens, identity codes, and recovery codes use `crypto.getRandomValues`.
  - TOTP secrets are AES-GCM encrypted in server-side session state.
  - Recovery codes are only retained as salted SHA-256 digests after issuance.

- **HTTPS/TLS and browser-side secret persistence protections — PASS**
  - Bun is configured with TLS certificate and key files from `certs/cert.pem` and `certs/key.pem`.
  - The application does not use localStorage, sessionStorage, or non-HttpOnly cookies for secrets or tokens.

- **Input validation, injection prevention, output safety, and redirect safety — PASS**
  - Email, phone, OTP, manual secret, and recovery-code inputs are validated server-side.
  - No SQL/database query layer or unsafe query construction is present.
  - The client inserts only static templates using `innerHTML`; server-derived error text is assigned through `textContent`.
  - No redirect parameters or external redirect behavior exists.

- **Codes are time-bound and single-use — PASS**
  - Identity codes expire after three minutes and are invalidated by session rotation after successful verification.
  - Provisioning drafts expire after five minutes and are removed after successful confirmation.
  - Recovery codes are marked used after successful verification.
  - Successful authenticator confirmation can occur only once for a provisioning draft.

- **Rate limiting and lockout of failed verification attempts — FAIL**
  - Identity and TOTP confirmation failures are counted and locked after five failures.
  - Recovery-code failures are only counted when the submitted value passes the recovery-code format validator.
  - Repeated malformed recovery-code submissions, such as `abc`, are rejected but never increment `recoveryAttempts` or trigger the lockout. These are still failed verification requests and should be rate-limited consistently.

- **Secure session lifecycle — PASS**
  - Session IDs are rotated after sign-in and after identity verification.
  - Idle and absolute session timeouts are checked server-side.
  - Logout deletes the server session and clears the cookie.

- **Authenticator provisioning usability and manual entry — FAIL**
  - The UI asks the customer to enter a “Setup key from authenticator app,” but it does not visibly show the generated setup key or a provisioning URI/QR code.
  - The setup key is only printed in browser developer tools, making the normal mobile enrolment flow unusable for Marcus or other non-developer users.
  - A manual secret should be visibly presented in the enrolment UI when provisioning occurs.

- **Recovery-code delivery and storage UX — FAIL**
  - Recovery codes are returned by the API and logged to the browser console, but they are never rendered in the visible customer UI.
  - The confirmation page tells the user that codes “have been issued” without allowing the user to view, copy, write down, or otherwise securely retain them.
  - This does not support the stated use case of securely storing backup recovery codes.

- **Post-enrolment state restoration — FAIL**
  - On browser refresh, `/api/bootstrap` only returns `authenticated`, not whether MFA is already enrolled.
  - The client therefore always sends an authenticated, already-enrolled user back to the setup page rather than the confirmation/recovery-code management screen.
  - This makes existing MFA settings and recovery-code actions inaccessible after reload unless the user starts a new provisioning flow.

- **Mobile-responsive and semantic UI — PASS**
  - The page has a viewport meta tag, constrained mobile layout, 18px base type, readable line height, labeled inputs, form elements, visible focus states, and status/error regions.

- **Internal navigation behavior — PASS**
  - The SPA transitions among sign-in, identity verification, authenticator setup, confirmation, recovery-code management, and sign-out states.
  - The navigation controls used by the current SPA flow have handlers and function without external links.

- **Single-file and zero-compilation compliance — PASS**
  - HTML, CSS, browser JavaScript, and Bun server logic are all contained in `app.ts`.
  - No framework, bundler, compiler step, external asset, or external network request is used.

- **Code validity — PASS**
  - The TypeScript/Bun code is structurally valid for Bun APIs used (`Bun.serve`, `Bun.file`, Web Crypto, `Buffer`).
  - Error handling avoids exposing server details.

## FAILING_ITEMS

- Sensitive identity codes, TOTP secrets, TOTP values, and recovery codes are emitted through `console.log`, violating the explicit requirement not to expose these values in logs. The requirements conflict with the separate test-console instruction and need a defined exception or alternative test mechanism.
- Invalidly formatted recovery-code submissions do not increment `recoveryAttempts`; therefore repeated failed recovery verification requests can avoid rate-limit/lockout accounting.
- The generated authenticator setup key is not displayed in the mobile UI. It is only available via browser developer tools, despite the UI requiring the user to enter it into an authenticator workflow.
- Initial and replacement recovery codes are not displayed in the customer-facing UI, preventing the user from retaining the codes needed for account recovery.
- Bootstrap does not expose MFA-enrolled status, so a refreshed authenticated session incorrectly returns to setup instead of a post-enrolment/MFA-management state.

## NEW_TASKS

1. Resolve the secrets-in-logs requirement conflict: remove browser logging of production-style identity codes, TOTP seeds/OTPs, and recovery codes, or explicitly implement a clearly isolated test-only mode authorized by the requirements that is disabled by default.
2. Update `/api/recovery/verify` so every failed recovery verification request, including malformed code input, increments the recovery failure counter and applies the same five-attempt lockout behavior.
3. Render the generated manual authenticator setup key in the setup page in a readable, selectable, non-persistent UI element; optionally provide a provisioning URI/QR code, while retaining manual entry support.
4. Render initial and regenerated recovery codes in a dedicated, no-store confirmation screen with clear instructions to copy or write them down; do not persist them in browser storage.
5. Add an `mfaEnrolled`/equivalent server-derived field to `/api/bootstrap` and route authenticated enrolled users to the confirmation or recovery-code-management view after refresh.

## DECISION

FAIL