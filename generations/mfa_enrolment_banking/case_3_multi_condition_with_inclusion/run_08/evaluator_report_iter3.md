## SUMMARY

The artifact is a single-file Bun application with inline HTML, CSS, and vanilla browser JavaScript. It implements a largely complete MFA enrolment flow with HTTPS/TLS, secure headers, authenticated server-side session state, CSRF checks, encrypted authenticator secrets, hashed recovery codes, TOTP verification, rate limiting, and mobile-oriented accessible UI. However, it does not fully meet the retry/re-request UX requirement: the “Show a new setup code” control does not work when clicked from the provisioning screen. Help is also not consistently available after dynamically rendered steps. Therefore, the artifact cannot be accepted as fully compliant.

## FUNCTIONAL_CHECK

- **PASS — Single-file application and zero-build setup**
  - The server, HTML template, CSS, and browser-side JavaScript all exist in `app.ts`.
  - Bun directly serves the application; there are no frameworks, external assets, bundlers, or separate client files.

- **PASS — Bun TLS server uses the specified certificates**
  - The server reads `certs/cert.pem` and `certs/key.pem` and provides them to `Bun.serve({ tls: ... })`.
  - This is consistent with the requirement to use the ready-made mkcert certificates.

- **PASS — Responsive, mobile-oriented, dyslexia-aware UI**
  - The page has a mobile viewport meta tag, constrained mobile-friendly content width, readable font sizing, spacing, visible focus states, short instructions, icons, and no animated/flashing content.
  - Inputs provide examples and relevant autocomplete attributes such as `autocomplete="one-time-code"` and password-manager-compatible login fields.

- **PASS — Sign-in, identity verification, authenticator provisioning, confirmation, and recovery-code flow**
  - The flow supports sign-in, mock identity code delivery, authenticator setup, TOTP confirmation, recovery code creation, settings, and recovery-code use.
  - Internal hash routes are constrained to an allow-list and render the relevant SPA screens.
  - Mock identity, TOTP, and recovery values are returned to the UI and written to the browser console through the `log()` function.

- **FAIL — Retry/re-request setup-code control works reliably**
  - On the provisioning screen, the “Show a new setup code” button calls `go("#setup")`.
  - The current URL hash is already `#setup` while the provisioning details are displayed. Assigning the same hash does not fire `hashchange`, so `render()` is not called and no new provisioning request occurs.
  - This means the user cannot re-request a new setup secret/code from that screen, contrary to the requirement to let users retry and re-request codes without penalty.

- **FAIL — Brief help is available at every step**
  - Help is initially added to the sign-in, identity request, setup request, and confirm screens.
  - However, dynamically replaced screens do not consistently include help. For example, after requesting the identity code, the replacement identity-entry UI has no help button; the provisioning-details, generated-recovery-codes, settings, recovery-code-use, saved, and completion screens also lack the common help affordance.
  - This does not meet the requirement that brief help or hints be easy to find at every step.

- **PASS — Manual alternative to QR provisioning is available**
  - The authenticator secret is visibly shown in grouped form, can be copied, and can be manually entered into an authenticator application if QR scanning is unavailable.
  - The UI also provides a copy action and the provisioning URI is used only to construct the QR code.

- **PASS — Verification is functional and protected against replay**
  - Identity codes are hashed, time-bound, single-use, and rate-limited.
  - TOTP verification accepts a narrow clock-skew window and tracks used TOTP time steps to prevent replay of a confirmed code.
  - Recovery codes are salted hashes and are marked used after successful submission.

- **PASS — Server-side authorization and IDOR prevention**
  - MFA endpoints derive the account exclusively from the authenticated server-side session.
  - The API does not trust a caller-supplied user/account identifier, and the `clean()` check rejects several likely identifier fields.
  - Session ownership is checked through `getSession()` and `accounts.get(session.accountId)` before protected operations.

- **PASS — CSRF protection for authenticated state-changing endpoints**
  - State-changing authenticated requests require the session-bound `X-CSRF-Token`.
  - The session cookie is `HttpOnly`, `Secure`, `SameSite=Strict`, and scoped to `/`.

- **PASS — Security headers and restrictive CORS**
  - Responses set CSP with a per-response nonce, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, and `Cache-Control: no-store`.
  - CORS only allows explicitly trusted local HTTPS origins.

- **PASS — Sensitive values are protected at rest and not stored in browser storage**
  - Authenticator secrets are encrypted with AES-GCM using a random server-process master key.
  - Recovery codes are stored as salted SHA-256 hashes.
  - Sensitive data is not placed in URLs, localStorage, sessionStorage, or non-HttpOnly cookies.
  - The browser console disclosure of mock values is explicitly required for this academic/demo artifact.

- **PASS — Session handling**
  - Session identifiers are cryptographically random and regenerated on sign-in.
  - Existing sessions for the demo account are removed at login.
  - Idle and absolute session expiry are implemented, and logout invalidates the server-side session and expires the cookie.

- **PASS — Input validation and output handling**
  - OTP and recovery-code formats are server-side validated.
  - Login values are length-bounded and compared to the mock account credentials.
  - Server-rendered dynamic values are inserted using `textContent` where applicable, reducing DOM XSS risk.
  - Redirect/navigation targets are restricted to a hard-coded internal hash-route set.

## FAILING_ITEMS

- The “Show a new setup code” control on the provisioning-details screen is non-functional because it navigates to the current hash (`#setup`) and therefore does not trigger a rerender or a new `/api/authenticator/provision` request.
- The application does not provide the required easy-to-find help/hint affordance at every dynamically rendered step.

## NEW_TASKS

1. Replace the provisioning-screen “Show a new setup code” handler with a handler that directly requests `/api/authenticator/provision` again, updates `provision`, logs the new mock secret/TOTP value in the browser console, and rerenders the provisioning details.
2. Add the consistent help control or an equivalent concise help/hint block to every rendered MFA step, including identity-code entry, QR/manual-key provisioning details, recovery-code display, settings, recovery-code use, and completion screens.
3. Ensure each dynamically inserted help control has its event handler attached after the relevant `innerHTML` replacement.

## DECISION

FAIL