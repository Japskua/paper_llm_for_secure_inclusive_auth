## SUMMARY

The artifact is a well-structured single-file Bun application with a functional recovery, reset, MFA, privacy acceptance, and appointment-confirmation flow. It includes HTTPS/TLS configuration, security headers, CSRF protection, input validation, browser-side mock logging, password hashing, and route/state controls. However, it does not fully meet the password-reset single-use security requirement under concurrent requests, and it embeds a known production-style account identifier and password directly in source. These are material security defects, so the artifact cannot be accepted as-is.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with inline HTML, CSS, and vanilla browser JavaScript.**  
  The complete application is contained in `app.ts`; it uses `Bun.serve`, returns an HTML page, and includes inline CSS and client logic. No framework, bundler, compiler step, external asset, or external network request is used.

- **PASS — TLS is configured using the required certificate locations.**  
  The server is created with `certs/cert.pem` and `certs/key.pem`, and it rejects requests whose URL protocol is not HTTPS.

- **PASS — Security response headers are present.**  
  The application configures HSTS, a nonce-based CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and no-store cache headers.

- **PASS — CSRF protection is implemented for sensitive POST endpoints.**  
  A random CSRF token is generated per server session and validated for all POST API actions, including recovery initiation, recovery verification, password reset, login, MFA confirmation, privacy acceptance, and appointment confirmation.

- **PASS — User-controlled content is not inserted as HTML.**  
  Browser-side rendering uses `textContent` and DOM-node creation rather than string interpolation of user input into HTML. The CSP restricts scripts to the server-issued nonce.

- **PASS — Password policy and password hashing are implemented.**  
  Passwords require 12–128 characters with uppercase, lowercase, numeric, and symbol characters. New passwords are hashed with Bun bcrypt before storage.

- **PASS — Login and verification attempts are throttled.**  
  Login failures are rate-limited by normalized identifier and client IP. Recovery-code and MFA-code verification also have attempt limits and lock periods.

- **PASS — The recovery token is random, stored hashed, and expires.**  
  Recovery tokens are generated with cryptographically secure random bytes, only their SHA-256 hashes are stored, and they expire after ten minutes.

- **FAIL — Recovery tokens are not reliably single-use under concurrent reset requests.**  
  In `/api/recovery/reset`, the code checks `validRecovery(session)` and then awaits `Bun.password.hash(...)` before setting `recovery.used = true`. Two concurrent reset requests using the same verified recovery state can both pass the validation before either request sets `used`. Both may therefore update the password. This violates the requirement that password-reset tokens be single-use.

- **FAIL — Known account credentials are hard-coded in application source.**  
  The source embeds both a predictable account identifier (`care-demo-4821`) and an initial plaintext password (`Temporary!Pass2026`). Even if intended for demonstration, these are reusable credentials for the only account in the application and conflict with the security expectation that authentication secrets are not exposed or hard-coded.

- **PASS — MFA is present and functional in the simulated environment.**  
  Login and password-reset flows require a second verification step. The deterministic mock MFA code is returned to the UI and logged in the browser, matching the mock-delivery requirement.

- **PASS — Mock recovery and MFA deliveries are logged in the browser.**  
  The client-side `audit()` function calls `console.log`, and the simulated recovery token/MFA code is displayed in the visible log panel and browser console.

- **PASS — Manual recovery-code entry works.**  
  Users can manually type the recovery token into the verification form. The simulated-link continuation is also available after a token is issued.

- **PASS — Internal navigation and protected step routing function.**  
  Hash-based routes are resolved through `/api/session`, and server-side state determines whether protected workflow steps such as reset, MFA, privacy, appointment, and completion can be viewed.

- **PASS — The UX generally supports a low-stress, guided workflow.**  
  The UI has explicit numbered progress, short instructions, visible feedback, accessible help/safety guidance, no visible countdown timer, pause-orientation persistence, and clear next steps.

- **PASS — No obvious runtime or syntax error is present.**  
  The TypeScript/JavaScript syntax is valid for Bun, browser APIs used by the client are supported, and the server routes and response helpers are internally consistent.

## FAILING_ITEMS

- **Password-reset token consumption is vulnerable to a concurrent-request race.**  
  `/api/recovery/reset` marks `recovery.used` only after awaiting bcrypt hashing. Parallel requests can both validate the same recovery state and both reset the password.

- **The application contains a hard-coded login identifier and plaintext default password.**  
  `DEMO_ACCOUNT_IDENTIFIER` and `"Temporary!Pass2026"` are embedded in source. A known password should not be deployed as an account credential, even in a simulated recovery portal.

## NEW_TASKS

1. **Make recovery-token consumption atomic before password hashing.**  
   In `/api/recovery/reset`, validate the verified recovery state and immediately mark it consumed (or replace it with a dedicated `resetInProgress`/consumed state) before the first `await`. If hashing fails, safely invalidate the recovery transaction rather than restoring a reusable token.

2. **Remove the hard-coded usable plaintext password from the application source.**  
   Initialize the demo account from a precomputed bcrypt hash, or generate a random startup-only password and log it only through the explicitly required browser-side mock process. Do not retain a known reusable password literal in `app.ts`.

3. **Avoid exposing a fixed deployable account identifier as a reusable credential.**  
   Either use an opaque randomly generated mock account identifier for the process lifetime, or clearly isolate deterministic test fixtures so they cannot serve as default authenticated credentials in a deployed instance.

## DECISION

**FAIL**