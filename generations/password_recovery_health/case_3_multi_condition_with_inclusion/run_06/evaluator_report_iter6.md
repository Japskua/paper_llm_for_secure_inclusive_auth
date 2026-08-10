## SUMMARY

The artifact is a strong single-file Bun implementation with secure server-side recovery state, CSRF validation, HTTPS/TLS setup, bcrypt password hashing, throttling, MFA verification, random reset tokens, safe browser-side mock delivery logging, and a clear low-stress recovery UI. However, it does not comply with the explicit requirement to be a Single-Page Application: recovery, login, and privacy acceptance are separate server-rendered documents navigated with `location.assign()`.

## FUNCTIONAL_CHECK

- **FAIL — UI must be a regular HTML/CSS/vanilla-JS Single-Page Application.**  
  The recovery flow itself is step-based within `/recovery`, but sign-in and privacy acceptance are separate pages served by `loginPage()` and `privacyPage()`. Client navigation uses full-document redirects such as `location.assign("/login")` and `location.assign("/privacy")`, rather than changing application state within one page.

- **PASS — Entire implementation is contained in one `app.ts` file.**  
  The Bun server, page templates, CSS, client JavaScript, API logic, account mock, TLS setup, and routing are all defined in the submitted file.

- **PASS — No framework, bundler, compiler pipeline, or external assets are required.**  
  The code uses Bun directly, standard Node/Bun modules, inline CSS, and a same-origin `/app.js` response generated from the `script` string. No external network resource or build tooling is used.

- **PASS — HTTPS is configured with the prescribed certificate paths and HTTP redirects to HTTPS.**  
  TLS reads `certs/cert.pem` and `certs/key.pem`; the HTTP server returns a `308` redirect to `https://localhost:3443`.

- **PASS — Secure response headers are configured.**  
  HTTPS responses include HSTS, CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, and no-store cache controls.

- **PASS — CSRF protection is present for sensitive actions.**  
  A session-specific random CSRF token is generated in `createSession()`, returned through `/api/session`, and checked by `guarded()` for every state-changing API route.

- **PASS — Recovery tokens are random, bound to a server-only account, short-lived, and single-use.**  
  Tokens use cryptographic random bytes, are associated with an internal account ID, expire after 15 minutes, are invalidated after password change, and require token verification plus MFA before password updates.

- **PASS — Recovery verification works through both the simulated link and manual token entry.**  
  The browser logs the returned mock recovery token, fills the token field after opening the simulated link, and allows the token to be manually entered in the recovery-code form.

- **PASS — Simulated recovery and MFA values are shown in the browser console.**  
  `delivery()` logs the simulated recovery token through browser `console.log`, and the MFA delivery handler logs the mock MFA code in the browser. The UI’s visible Logs section also records these practice values.

- **PASS — Password policy and password storage are appropriately implemented.**  
  Passwords require at least 12 characters with uppercase, lowercase, numeric, and symbol characters and no whitespace. Passwords are hashed using Bun’s bcrypt support and are not logged.

- **PASS — Authentication failures and automated guessing are throttled.**  
  Verification and login actions use per-session and global counters with lock periods. Recovery and MFA code issuance also have separate issuance limits.

- **PASS — The system avoids user/account enumeration and private identifier exposure.**  
  Recovery requests return a generic response for matched and unmatched contacts. Browser responses do not expose account IDs, usernames, or the registered recovery channel.

- **PASS — XSS protections are adequate for the supplied UI.**  
  User input is not inserted into HTML. Browser log entries use `textContent`, reset values are URL-encoded, CSP restricts scripts to same-origin resources, and no untrusted script content is executed.

- **PASS — Accessibility and ADHD-focused recovery guidance are substantially addressed.**  
  The recovery UI provides numbered steps, visible orientation text, clear feedback, low-density instructions, an always-visible help section, no countdown timer, progress restoration from server state, and a dedicated visible event log.

- **PASS — Internal recovery, sign-in, privacy acceptance, and logout routes function correctly.**  
  The recovery link route, manual verification flow, login endpoint, privacy acceptance action, authenticated access check, and logout flow are all wired to existing routes and server handlers.

## FAILING_ITEMS

- **The application is not a Single-Page Application.**  
  `/recovery`, `/login`, and `/privacy` are distinct server-rendered HTML documents. The browser performs full navigation via `location.assign()`, including after password reset, successful login, unauthorized privacy-page access, and logout.

## NEW_TASKS

1. Refactor the client UI into one application page containing recovery, login, and privacy views, with only the active view shown at a time.
2. Replace full-page `location.assign("/login")`, `location.assign("/privacy")`, `location.assign("/recovery")`, and related page redirects with client-side view/state transitions.
3. Update server routing so the SPA shell is served for the application routes, while retaining `/api/*` routes and the same-origin JavaScript endpoint.
4. Preserve the current server-side authentication and recovery-state checks while having the client render the appropriate recovery, login, or privacy view based on `/api/session` state.

## DECISION

**FAIL**