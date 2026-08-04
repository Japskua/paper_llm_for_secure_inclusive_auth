## SUMMARY

The artifact is a single `app.ts` Bun HTTPS server with substantial security-oriented server logic, including CSRF validation, TLS certificate loading, secure cookies, CSP/security headers, bcrypt password hashing, reset-token expiry/single-use controls, MFA, and throttling. However, it contains a fatal JavaScript syntax error in the browser script, so the SPA does not initialize and the recovery flow cannot be used. There are also state-isolation and compliance issues.

## FUNCTIONAL_CHECK

- **FAIL — Single-file Bun server with inline HTML/CSS/vanilla JavaScript**
  - The implementation is contained in one `app.ts` and does not use frameworks, external assets, bundlers, or external network calls.
  - However, the inline browser JavaScript has a syntax error, so the single-page app is not functional.

- **PASS — Bun HTTPS server uses the provided TLS certificate paths**
  - The server loads `certs/cert.pem` and `certs/key.pem` and configures `Bun.serve({ tls: ... })`.
  - It fails safely without starting if the certificate files are missing.

- **FAIL — Password recovery UI and multi-step flow work in the browser**
  - The client script contains a malformed expression in Step 3:
    ```js
    ||! / .test(" ")&& !/[^A-Za-z0-9]/.test(x)
    ```
  - This prevents the script from parsing, so bootstrap, rendering, navigation, forms, logs, API calls, and all recovery interactions fail.

- **FAIL — Recovery token can be manually submitted and verified**
  - The server endpoint `/api/recovery/verify-token` correctly supports manual token entry and validates a random, single-use, expiring token.
  - In practice, the browser UI cannot render because of the JavaScript parse error, so the required manual-submission UX does not work.

- **FAIL — Simulated delivery values are shown via browser `console.log`**
  - The intended client code does log the reset token and MFA code in the browser.
  - Because the client script cannot parse, these browser logs never execute.
  - In addition, `regressionChecks()` logs simulated state results to the Bun/server console, conflicting with the requirement that mocks be logged in the browser.

- **PASS — Reset-token security**
  - Reset tokens are generated using `randomBytes`, are 64 hex characters, have a 15-minute lifetime, and are marked consumed before a successful response is returned.
  - Token verification checks session-bound recovery state, token expiry, account eligibility, and prior consumption.

- **PASS — CSRF/session protections for sensitive requests**
  - Sensitive `POST` endpoints require a session and `X-CSRF-Token`.
  - CSRF values are random per session and compared using `timingSafeEqual`.
  - Cookies are `Secure`, `HttpOnly`, `SameSite=Strict`, and scoped to `/`.

- **PASS — Core security headers and HTTPS protections**
  - HSTS, CSP, `X-Content-Type-Options`, frame protections, referrer policy, permissions policy, and no-store cache headers are configured.
  - The CSP uses a per-page nonce for the trusted application script.

- **PASS — Password hashing, password policy, MFA, and throttling**
  - Password updates use Bun bcrypt hashing.
  - Password policy requires 12+ characters with uppercase, lowercase, number, and symbol.
  - A six-digit simulated MFA code is required before saving the password.
  - Login, token, MFA, password-update, and recovery-initiation actions are rate limited.

- **FAIL — Privacy acceptance is properly access-controlled and isolated**
  - `privacyAccepted` is a process-global variable:
    ```ts
    let privacyAccepted = false;
    ```
  - If one authenticated session accepts privacy conditions, every other authenticated session will resolve to the `"complete"` stage. Privacy acceptance must be scoped to the authenticated account/session, not global server state.

- **FAIL — ADHD-inclusive recovery experience is operational**
  - The static design includes step progress, calm language, help text, saved server-side stage state, and no client timer.
  - Because the SPA script fails to parse, users cannot receive step feedback, progress updates, help in context, pause/resume behavior, or complete the flow.

- **FAIL — Clear comments map implementation to requirement sections**
  - Some comments describe security behavior, but the artifact does not clearly map the implementation to the requested requirement sections, especially inclusivity, SSRF/social-engineering guidance, and the individual security categories.
  - The existing top-level comment is only a broad summary rather than a clear requirements mapping.

## FAILING_ITEMS

- The browser JavaScript has a fatal syntax error in the Step 3 password-policy condition:
  ```js
  ! / .test(" ")&& !/[^A-Za-z0-9]/.test(x)
  ```
  This stops the entire SPA from loading.

- Privacy acceptance is stored globally in `privacyAccepted`, allowing acceptance in one authenticated session to affect other authenticated sessions.

- The required browser-side simulated logs never run because the client script does not parse.

- `regressionChecks()` emits simulated/mock results through Bun’s server-side `console.log`, despite the deliverable requirement that mocks be logged in the browser.

- The code comments do not clearly map the code to all requested requirement sections.

## NEW_TASKS

1. Replace the malformed Step 3 password validation expression with a valid symbol check, for example:
   ```js
   if (
     x.length < 12 ||
     !/[a-z]/.test(x) ||
     !/[A-Z]/.test(x) ||
     !/\d/.test(x) ||
     !/[^A-Za-z0-9]/.test(x)
   ) {
     return render("Use at least 12 characters with uppercase, lowercase, number, and symbol.", "error");
   }
   ```

2. Test the page in a browser after the syntax correction and verify that bootstrap, progress navigation, token logging, MFA logging, password update, sign-in, and privacy acceptance all execute.

3. Move `privacyAccepted` from process-global state into the relevant authenticated account/session record so one session’s acceptance cannot alter another session’s stage.

4. Remove the server-side mock/regression `console.log` output or implement equivalent browser-side test logging so simulated delivery and verification logs comply with the browser-console requirement.

5. Add concise comments explicitly mapping the server and UI sections to the stated requirements: inclusivity/ADHD UX, CSRF/access control, XSS/output safety, secure configuration/TLS, authentication/MFA/throttling, and social-engineering guidance.

## DECISION

**FAIL**