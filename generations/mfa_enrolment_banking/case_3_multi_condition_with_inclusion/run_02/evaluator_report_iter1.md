## SUMMARY

The artifact is a single-file Bun application with a clear mobile-oriented MFA enrolment UI, session-bound MFA state, CSRF checks on post-login MFA actions, secure cookie attributes, security headers, encrypted OTP-secret storage, and browser-side mock logging. However, it does not fully meet the requirements because it can run over insecure HTTP, its login endpoint grants access to Marcus’s account for any syntactically valid email, its QR image is not a valid scannable QR code, and some recovery/privacy/security requirements are incomplete.

## FUNCTIONAL_CHECK

- **Single `app.ts` Bun server with inline HTML, CSS, and vanilla JavaScript, with no external assets/build tools — PASS**
  - The entire server and client application are contained in `app.ts`.
  - It uses `Bun.serve`, inline CSS, and inline browser JavaScript.
  - No framework, build tool, compilation pipeline, database, or external network request is used.

- **Responsive, legible mobile web UI — PASS**
  - The page includes a viewport meta tag, a narrow `max-width: 540px` layout, mobile spacing, large controls, and a small-screen media query.
  - Inputs and buttons have a minimum height of 51px, which is appropriate for mobile interaction.

- **Dyslexia-aware, low-reading-load UX — PARTIAL / FAIL**
  - The UI uses short instructions, visible step labels, plain language, icons, generous line spacing, examples for inputs, keyboard/autofill hints, and no moving or flashing content.
  - However, the application permanently renders a “Logs” card containing sensitive long secrets, OTPs, and recovery codes. This adds clutter and increases reading burden.
  - The setup secret cannot be hidden/revealed, and recovery codes cannot be re-requested through the UI without restarting/reprovisioning.
  - Retry behavior is not always step-preserving: a verification error sends the user back through provisioning, generating a new secret rather than allowing a straightforward retry with the current setup.

- **Authenticator provisioning offers QR and manual setup support — FAIL**
  - The setup key is displayed and can be copied, and the provisioning URI can be copied.
  - The displayed QR graphic is not a standards-compliant QR encoding. `qrSvg()` creates a decorative/pseudo-random SVG pattern rather than a scannable QR code containing the provisioning URI.
  - Therefore, users cannot actually scan the offered QR code with an authenticator app.

- **Mock OTP and recovery values are shown in the browser console and UI — PASS**
  - `addLog()` calls browser `console.log`.
  - The setup secret, deterministic mock OTP, and recovery codes are logged in the browser.
  - The mock OTP and recovery codes are returned to the UI, allowing the flow to be tested.

- **MFA verification works, is single-use, time-bound, and rate-limited — PARTIAL / FAIL**
  - Verification accepts a six-digit code, expires provisioning after 10 minutes, prevents reuse through `usedOtps`, and locks the user out after five failures for five minutes.
  - However, the OTP is always the globally predictable value `123456`; it is not generated with sufficient entropy.
  - The implementation does not implement a real TOTP calculation from the provisioned secret, so a scanned/manual authenticator setup will not produce a valid code for the server.

- **Backup recovery codes are securely generated and stored — PARTIAL / FAIL**
  - Recovery codes are generated from `crypto.getRandomValues`, displayed once in the UI, and stored as hashes rather than plaintext.
  - However, they are hashed with unsalted raw SHA-256. A password/KDF-style hash with a unique salt per code is more appropriate for recovery credentials.
  - There is no endpoint or flow to submit and consume a recovery code, so the claimed “each code works once” behavior is not implemented or verifiable.
  - The backup-code endpoint will issue a new set repeatedly, but the UI does not present a clear, intentional “request new codes” action or explain that previous codes are replaced.

- **Server-side authorization and IDOR prevention — FAIL**
  - MFA routes do derive the account identity from the server-side session and do not accept a client-controlled user ID.
  - However, `/api/login` accepts any syntactically valid email and always creates a session for `userId: "marcus-account"`.
  - For example, `attacker@example.com` can obtain a session authorized for Marcus’s MFA state. This is a broken authentication and authorization boundary, not proof that the caller owns Marcus’s account.

- **CSRF protection for state-changing requests — PARTIAL / FAIL**
  - `/api/mfa/provision`, `/api/mfa/verify`, `/api/mfa/backup-codes`, and `/api/logout` require the session’s `X-CSRF-Token`.
  - `/api/login` is also state-changing because it creates an authenticated session, but it has no CSRF validation or equivalent origin-based protection.
  - The requirement calls for CSRF protection on all state-changing requests.

- **Secure session handling — PARTIAL / FAIL**
  - Sessions use cryptographically random IDs, rotate on login, use `HttpOnly; Secure; SameSite=Strict`, enforce idle and absolute expirations, and are invalidated on logout.
  - However, the server falls back to plain HTTP if certificate files are unavailable. On HTTP, the `Secure` session cookie will not be sent by the browser, so login/MFA functionality will not work correctly.
  - Allowing HTTP at all violates the HTTPS/TLS requirement.

- **HTTPS/TLS and security headers — PARTIAL / FAIL**
  - When `certs/cert.pem` and `certs/key.pem` are present, the server configures Bun TLS correctly.
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, and a restricted CORS origin are present.
  - However, the application deliberately starts as HTTP when certificates are missing. It must fail closed or otherwise enforce HTTPS rather than serving insecurely.

- **No server-side exposure of secrets in logs, URLs, or error messages — PARTIAL / FAIL**
  - The server does not log secrets, does not place them in query strings, and returns generic server errors.
  - However, the rendered page includes a visible “Logs” panel containing the setup secret, OTP, and recovery codes. The requirement specifically asks that sensitive MFA values not be exposed in logs.
  - Browser `console.log` is explicitly required for the academic mock, but sensitive values do not also need to be rendered in a persistent on-screen log panel.

- **Server-side validation and output escaping — PASS**
  - Email and OTP inputs are validated server-side.
  - The server does not use SQL or dynamic query construction.
  - Client-rendered dynamic values are escaped with `escapeHtml`, while direct text output uses `textContent`.
  - No user-controlled redirect target is accepted.

- **Generic production errors and no verbose stack traces — PASS**
  - The Bun `error()` handler returns a generic message.
  - API errors are controlled and do not expose stack traces or internal values.

## FAILING_ITEMS

- The server starts insecure HTTP when TLS certificates are absent. This violates mandatory HTTPS/TLS enforcement and prevents `Secure` session cookies from functioning on that fallback server.
- `/api/login` authenticates any valid email as the fixed `marcus-account`, allowing an arbitrary caller to access and modify Marcus’s MFA state.
- The login endpoint has no CSRF or equivalent origin protection despite creating an authenticated session.
- The “QR code” is not an actual QR code and cannot be scanned by an authenticator app.
- The server accepts only the static OTP `123456`; it does not validate a TOTP derived from the provisioned secret and does not use an unpredictable OTP value.
- Recovery codes are stored with unsalted raw SHA-256 rather than a salted, slow credential hash/KDF.
- Recovery codes cannot be submitted and consumed, so one-time recovery-code behavior is not implemented.
- The UI has no explicit hide/reveal control for the setup secret and no clear re-request/regenerate recovery-code path.
- Verification retry errors return to provisioning and replace the setup secret rather than preserving the user’s current verification step.
- The persistent on-screen “Logs” card displays secrets, OTPs, and recovery codes, creating unnecessary sensitive-data exposure and visual clutter.

## NEW_TASKS

1. Remove the HTTP fallback: require `certs/cert.pem` and `certs/key.pem` at startup, start only with Bun TLS, and fail closed with a generic startup error if certificates are unavailable.

2. Replace the arbitrary-email login behavior with a mock authentication/identity-verification flow that only creates a session for the verified account owner; do not map every valid email to `marcus-account`.

3. Add CSRF protection or strict server-side Origin validation to `/api/login`, since it creates an authenticated session.

4. Replace `qrSvg()` with a self-contained, standards-compliant QR encoder that encodes the returned `otpauth://` provisioning URI and can be scanned by common authenticator applications.

5. Implement server-side authenticator verification based on the provisioned secret, using a real TOTP calculation or a per-provisioning cryptographically random mock OTP; retain browser-console test logging without using a globally predictable `123456` code.

6. Store recovery codes using a unique salt and a slow password-hashing/KDF mechanism, and add a CSRF-protected recovery-code verification endpoint that atomically consumes a valid code after one use.

7. Add explicit UX controls to hide/reveal the setup secret and to re-request/regenerate recovery codes, with clear wording that regenerated codes replace prior codes.

8. Preserve the current setup state when an OTP verification attempt fails so “Try again” returns the user to the same code-entry screen instead of reprovisioning a new secret.

9. Remove the visible persistent sensitive-data log panel from the rendered UI. Keep required mock-value output in the browser’s developer console only, and do not render secrets, OTPs, or recovery codes as log entries.

## DECISION

FAIL