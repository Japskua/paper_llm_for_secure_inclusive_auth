## SUMMARY

The artifact is a well-structured single-file Bun HTTPS application with a functional simulated recovery flow, CSRF protection, secure cookies, CSP/security headers, random short-lived reset tokens, token/MFA verification, password hashing, and client-side XSS-safe rendering. However, it does not fully meet the functional and security requirements: the “Start another recovery” action cannot actually start a new recovery after completion, simulated delivery state is not recoverable after a page reload, and reset-code request endpoints can be automated without meaningful request throttling. Therefore, the artifact cannot be accepted as-is.

## FUNCTIONAL_CHECK

- **Single `app.ts` artifact containing Bun server, HTML, CSS, and vanilla browser JavaScript: PASS**
  - The complete server and client application are contained in one file. Imports are built-in Node/Bun-compatible modules only; no framework, bundler, compiler, or external assets are used.

- **Bun directly serves interactive HTML/CSS/JS: PASS**
  - The HTTPS server serves the HTML at `/` and `/recovery`, and serves the client script at `/app.js`. The browser logic uses standard DOM APIs and `fetch`.

- **TLS certificate usage and HTTPS enforcement: PASS**
  - The server reads `certs/cert.pem` and `certs/key.pem` and configures Bun TLS.
  - The HTTP listener redirects to a fixed HTTPS localhost URL with status `308`.

- **Secure response headers / security misconfiguration protections: PASS**
  - HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and no-store cache controls are configured.
  - The CSP only permits same-origin scripts, and the JavaScript is served from `/app.js`.

- **CSRF protection for sensitive requests: PASS**
  - A random CSRF token is generated per server-side session.
  - All state-changing API routes use `protectedRequest()` and validate the `X-CSRF-Token` header.
  - The session cookie is `HttpOnly`, `Secure`, `SameSite=Strict`, and path-scoped.

- **Sensitive state is server-authoritative / no obvious IDOR: PASS**
  - Reset records, verified-token state, MFA state, and attempts are retained server-side per session.
  - A reset token is only accepted when it belongs to the current session’s reset record.

- **XSS and unsafe rendering protections: PASS**
  - Client-side dynamic content is inserted with `textContent`, not `innerHTML`.
  - User-supplied contact input is never reflected into the page or API response.
  - No user-controlled redirect target is accepted.

- **Random, short-lived, single-use reset tokens: PASS**
  - Tokens are generated using `randomBytes(32)`, expire after 15 minutes, are invalidated when replaced, and are marked used after the password change.

- **Manual recovery-code submission and simulated recovery-link behavior: PASS**
  - The reset code can be manually entered.
  - The simulated recovery-link button navigates only to a fixed same-origin `/recovery?reset=...` route and automatically verifies the token in the same browser session.

- **MFA step is implemented: PASS**
  - The flow requires a reset-token verification step followed by an MFA/security-code verification before allowing a password change.
  - The deterministic MFA code is returned to the browser and logged there for the simulation.

- **Strong password policy and bcrypt hashing: PASS**
  - Passwords require at least 12 characters, uppercase, lowercase, numeric, and symbol characters, with no whitespace.
  - The resulting password is stored as a bcrypt hash through `Bun.password.hash`; plaintext passwords are not persisted.

- **Login and verification guessing protections: PASS**
  - Login, reset-token verification, and MFA verification use per-session and cross-session attempt controls.
  - Failed attempts produce lockouts after configured thresholds.

- **Reset-request abuse protection: FAIL**
  - `/api/recovery/request` and `/api/recovery/request-another` call `permitted()` but never record a request attempt or otherwise consume quota on successful requests.
  - An automated client can repeatedly request new reset tokens and repeatedly invalidate existing tokens without being rate-limited. This is an abuse/flooding weakness in the password-reset flow.

- **Clear, low-stress, ADHD-oriented recovery UX: PARTIAL / FAIL**
  - The stepper, orientation message, help panel, no client-side countdown, clear labels, and status feedback are good.
  - However, progress recovery is incomplete after refresh: server state restores step 2, but the simulated reset token/link and activity log are not restored. In this demo, the code is only delivered through the prior browser console/activity log, so a reload can leave the user unable to continue without requesting another code.
  - This conflicts with the requirement to let users pause and return without losing progress.

- **“Start another recovery” action works: FAIL**
  - After a password reset, `session.reset.used` remains true.
  - Clicking `#restart` only removes `localStorage` state and navigates to `/`; it does not create a fresh server session or clear/revoke the existing completed recovery state.
  - On reload, `/api/session` reports `recoveryState: "finished"`, so the UI returns to step 5 rather than allowing a new recovery request.

- **Mocks are delivered/logged in the browser: PARTIAL / FAIL**
  - The browser does log `mockDeliveryToken` and `mockMfaCode`, satisfying the testing visibility requirement.
  - However, server-side `console.log` calls also describe simulated password-reset and MFA delivery. The requirement specifically states that mocks should use `console.log` **in the browser**. Delivery simulation logging should be client-side only.

- **No external network calls / open redirects: PASS**
  - Browser requests are same-origin API calls only.
  - The simulated recovery navigation uses a fixed same-origin route and URL-encodes the token.

- **Code validity / runtime concerns: PASS with minor caveat**
  - The TypeScript/JavaScript structure is syntactically coherent and routes are consistently handled.
  - `Bun.password` usage is plausible for Bun 1.3.0 and bcrypt is explicitly requested.
  - No immediate compile/runtime-breaking defect is apparent from inspection.

## FAILING_ITEMS

- **The completed-flow restart control is nonfunctional.**
  - `#restart` navigates back to `/` but retains the same `recovery_session` cookie and completed reset state.
  - The server consequently restores the “finished” state forever for that session instead of starting a new recovery.

- **The pause/resume experience loses the simulated delivery artifact after reload.**
  - `lastToken`, the “Open simulated recovery link” visibility, and the activity log are memory-only.
  - After a reload at step 2, the server correctly restores the recovery-code step, but the user no longer sees the mock token or link needed to continue in the demonstration.

- **Recovery request endpoints do not effectively throttle automated request floods.**
  - Request endpoints check `permitted()` but successful request actions do not increment an attempt counter.
  - Repeated requests can continuously generate replacement tokens and simulated deliveries.

- **Mock delivery events are also logged on the server.**
  - The specification requires mock delivery/testing console output in the browser. Server-side delivery/MFA simulation logs should be removed or limited to non-mock operational security events.

## NEW_TASKS

1. Add a protected `POST /api/recovery/restart` endpoint that invalidates the current completed recovery state and rotates to a new session ID and CSRF token; update the Restart button to call it before navigating to step 1.

2. Preserve the simulated reset delivery token/link for the active recovery state across a same-browser page reload, or provide a secure server-authoritative testing-only retrieval action for the current session that returns the active mock token and repopulates the activity log/link at step 2.

3. Implement request-rate throttling for `/api/recovery/request` and `/api/recovery/request-another`, including recording successful requests and applying both session and cross-session limits before issuing another reset token.

4. Remove server-side `console.log` statements that simulate reset-code or MFA delivery, and retain browser-side `console.log` output for the deterministic mock token and MFA code.

## DECISION

**FAIL**