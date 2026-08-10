## SUMMARY

The artifact is a single-file Bun HTTPS SPA with a generally strong security structure: authenticated server-side sessions, CSRF checks, secure cookies, TLS, input validation, hashed/encrypted server-side secrets, rate limiting, and clear mobile-oriented UI. However, it does not fully meet the enrolment and security requirements. In particular, the claimed QR setup image is not a standards-compliant QR code, users can become stuck after refreshing or expiring the authenticator setup step, and the identity-verification lockout can be bypassed through the resend endpoint. Its CSP also blocks its own inline/dynamic progress-bar styles.

## FUNCTIONAL_CHECK

- **Single `app.ts` containing Bun server, HTML, CSS, and vanilla client JavaScript — PASS**
  - The supplied artifact is one `app.ts`, uses `Bun.serve`, and embeds the HTML/CSS/JS in the file. No framework, bundler, compiler pipeline, or external assets are used.

- **HTTPS/TLS using the provided certificate paths — PASS**
  - `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`.
  - The server only exposes HTTPS through Bun TLS configuration.

- **Responsive, mobile-oriented UI — PASS**
  - The page has a mobile viewport meta tag, constrained mobile layout (`width:min(100%, 540px)`), mobile media query, sufficiently large controls, and generous spacing.

- **Dyslexia-conscious UI and plain-language guidance — PASS**
  - The UI uses readable sizing, expanded letter/line spacing, examples for email/phone/code entry, predictable steps, help disclosures, no animation/timers, visible step progress, and clear error messages.
  - There is no reading-time limit.

- **One clear primary action per screen and clear progress — PASS**
  - Each main state presents a primary submit/action button and shows “Step X of 6.”
  - Secondary actions such as resending/copying/regenerating are visually secondary.

- **Mock delivery is available in browser console and visible UI — PASS**
  - Identity code, authenticator secret/OTP, and recovery codes are sent to the UI and logged with browser-side `console.log`, as explicitly required for the mock/testing flow.
  - The server itself does not log these values.

- **Identity code verification works, is single-use, and is time-bound — PASS**
  - The identity code is hashed server-side, expires after 15 minutes, is marked used after success, and is checked server-side.

- **Authenticator OTP verification works, is single-use, and is time-bound — PASS**
  - The mock OTP is verified server-side, expires after 15 minutes, and is marked used after success.
  - Deterministic mock values are permitted by the stated simulation requirement.

- **Authenticator setup provides a genuine QR-code provisioning option — FAIL**
  - `drawQr()` draws a deterministic pseudo-random grid with finder-like patterns, not a valid QR encoding.
  - The UI tells users to scan it in an authenticator app, but a real authenticator cannot scan/use it as a provisioning QR code.
  - No `otpauth://` provisioning URI is generated or encoded.

- **Manual authenticator-secret entry and copy support — PARTIAL / FAIL**
  - A copyable manual secret is shown, which is good.
  - However, it is paired with a non-functional “QR-style” image and does not provide a standard provisioning URI/account metadata needed for ordinary authenticator setup.

- **Users can retry, reveal, hide, and re-request codes without becoming stuck — FAIL**
  - If the page is refreshed during the `otp` stage, `setupSecret` is only held in JavaScript memory and becomes empty.
  - There is no UI action or valid API route to regenerate setup details while the session remains at `otp`.
  - If the OTP expires, the server says to “go back and make a new setup code,” but the UI provides no route to do so.
  - The only described workaround is signing in again, but there is no sign-out/restart action on that screen.

- **Recovery codes can be regenerated and are stored securely server-side — PASS**
  - Recovery codes are generated using cryptographic randomness, only salted hashes are retained server-side, old codes are replaced on regeneration, and the UI supports copy actions.
  - After refresh, users can create a replacement set, although the initially issued visible set is not recoverable by design.

- **Server-side authorization on MFA endpoints / no client-controlled owner ID — PASS**
  - Protected MFA routes use `requireOwner()`.
  - The authenticated user ID is created server-side and requests containing `userId` or `accountId` are rejected.
  - The application does not trust a client-supplied account identifier, preventing the identified IDOR class.

- **CSRF protection for state-changing requests — PASS**
  - Mutation requests require the session CSRF token and a trusted origin.
  - Session cookies use `SameSite=Strict`, providing additional CSRF mitigation.

- **Secure response headers and clickjacking protection — PARTIAL / FAIL**
  - HSTS, `X-Content-Type-Options: nosniff`, CSP, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, cache prevention, and a restrictive permissions policy are present.
  - However, the CSP’s `style-src 'nonce-...'` blocks inline style attributes and dynamically injected style attributes. The HTML includes `style="width:16%"`, and JavaScript uses `bar.style.width = ...`.
  - This creates CSP violations and means the application’s progress-bar styling is not CSP-compatible as written.

- **Session security — PASS**
  - Session IDs are random, stored only in `HttpOnly; Secure; SameSite=Strict` cookies, rotated after sign-in, expire on idle/absolute timeout, and are invalidated on logout.
  - No session token is stored in localStorage/sessionStorage or client-readable cookies.

- **Secrets protected at rest and not persisted in browser storage — PASS**
  - The authenticator secret is AES-GCM encrypted in server memory; recovery codes are salted and hashed.
  - Sensitive values are not stored in `localStorage`, `sessionStorage`, or non-HttpOnly cookies.
  - Browser-console/UI disclosure is deliberate test behavior required by the mock-delivery deliverable.

- **Input validation, XSS handling, and redirect handling — PASS**
  - The server validates email, phone, OTP, and recovery-code formats.
  - Client-provided owner/account/redirect fields are rejected.
  - The app has no client-controlled redirects.
  - Dynamic UI rendering is limited to server-controlled/static values and constrained generated codes; no direct rendering of arbitrary user input was identified.

- **Rate limiting and lockout of failed verification attempts — FAIL**
  - `failAndMaybeLock()` correctly locks a session after five failed attempts.
  - However, `/api/identity/resend` does not check `locked(session)` and resets `identityFailures = 0`.
  - An attacker/user can submit five incorrect identity codes, call the resend endpoint, and immediately resume attempts, bypassing the intended five-minute lockout.
  - `/api/identity/resend` also lacks a stage check, allowing it outside the identity stage.

- **Generic production error handling and no verbose stack traces — PASS**
  - The top-level server handler catches errors and returns generic messages without stack traces or debug output.

- **CORS restricted to trusted origins — PASS**
  - Requests with untrusted `Origin` headers are rejected.
  - The application does not permit arbitrary origins.

## FAILING_ITEMS

- The displayed “QR-style authenticator setup image” is not a valid QR code and does not encode a usable authenticator provisioning URI. The UI incorrectly instructs users to scan it with an authenticator app.

- The authenticator setup flow is not recoverable after a refresh or OTP expiry:
  - `setupSecret` exists only in client JavaScript memory.
  - The `otp` screen has no “get new setup details” / restart setup action.
  - `/api/authenticator/setup` only works at `stage === "setup"`.
  - The server’s expiry message instructs the user to take an action that the UI does not offer.

- The failed-attempt lockout is bypassable:
  - `/api/identity/resend` neither checks whether the session is locked nor limits resend behavior.
  - It resets `identityFailures`, defeating the verification lockout.
  - It does not require `session.stage === "identity"`.

- The CSP is inconsistent with the application’s own styles:
  - `style-src 'nonce-...'` does not authorize the inline `style="width:16%"` attribute.
  - Dynamic `bar.style.width` assignments are likewise incompatible with the restrictive style policy.
  - This produces browser CSP violations and prevents reliable progress-bar rendering.

## NEW_TASKS

1. Replace `drawQr()` with an in-file standards-compliant QR encoder that encodes a real `otpauth://totp/...` provisioning URI, including the issuer, account label, Base32 secret, algorithm, digits, and period. Keep the copyable Base32 secret and provide a copyable provisioning URI as an additional manual/setup option.

2. Add an authenticated, CSRF-protected “get new authenticator setup details” endpoint and corresponding `otp`-screen UI action. It must securely rotate the existing setup secret/OTP challenge, issue fresh mock setup details, and allow recovery from page refresh or OTP expiry without requiring an unrelated re-login.

3. Enforce the lockout on `/api/identity/resend`; do not reset identity failure counters while a lock is active. Add a `session.stage === "identity"` check to both identity verification and identity resend routes, and return the existing clear lockout/earlier-step messages when inappropriate.

4. Make progress-bar styling CSP-compatible. Remove the inline `style` attribute and replace dynamic `bar.style.width` mutations with predefined nonce-authorized CSS classes or another CSP-compliant rendering mechanism.

## DECISION

FAIL