## SUMMARY

The artifact is a single-file Bun HTTPS SPA with a generally strong security-oriented server implementation: bcrypt password hashing, CSRF tokens, CSP/nonces, secure cookies, reset-token hashing/expiry/single use, and MFA are present. The recovery flow, simulated browser console delivery, manual code entry, pause/resume, and accessibility-oriented UI are substantially implemented. However, the client-side route/state handling is faulty and allows unauthenticated users to navigate directly to misleading privacy and completion screens. It also fails to preserve recovery-stage state in the client, which breaks pausing at the privacy step. Additionally, throttling can be bypassed through attacker-controlled request headers.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun implementation with no framework, bundler, compiler, external assets, or network calls.**  
  The server, HTML, CSS, and vanilla browser JavaScript are all contained in `app.ts`. The only import is Node-compatible built-in `crypto`, and TLS files are referenced exactly from the required `certs/cert.pem` and `certs/key.pem` locations.

- **PASS — Bun HTTPS server configuration is present.**  
  `Bun.serve` is configured with `hostname: "localhost"`, TLS certificate/key files, and serves the SPA over HTTPS. HSTS is also returned on responses.

- **PASS — Password recovery supports both simulated delivery and manual code submission.**  
  `/api/recovery-request` creates a random reset token, returns it to the browser, and the browser logs it with `console.log`. The `/verify` page provides a manual recovery-code form.

- **PASS — Reset tokens are random, hashed, session-bound, short-lived, and single-use.**  
  Tokens are created with `randomBytes`, stored as bcrypt hashes, expire after 15 minutes, are bound to a session, and are marked both `verified` and `used` after successful verification.

- **PASS — Password policy and bcrypt password storage are implemented.**  
  Passwords require 12+ characters with uppercase, lowercase, number, and symbol. Stored account passwords are bcrypt hashes using `Bun.password.hash`; plaintext passwords are not stored.

- **PASS — MFA is implemented for normal sign-in.**  
  Successful password sign-in creates an MFA challenge, requires code verification, limits unsuccessful attempts, and only then marks the session authenticated.

- **PASS — CSRF protection is implemented for state-changing API requests.**  
  Sessions have unique CSRF tokens, POST API routes require `X-CSRF-Token`, and same-origin validation is performed where an `Origin` header is supplied. Session cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`.

- **PASS — XSS and response-header protections are substantially implemented.**  
  User-rendered messages are escaped through `esc`, input validation rejects HTML-control characters, CSP uses nonces rather than `unsafe-inline`, and security headers include CSP, `X-Frame-Options`, `nosniff`, `Referrer-Policy`, and restrictive permissions policies.

- **FAIL — Sensitive SPA screens are not access-controlled or state-gated in the browser.**  
  Any visitor can manually navigate to `#/privacy` or `#/confirmation`. `#/confirmation` unconditionally renders “Privacy conditions accepted” even if the session is unauthenticated and has never accepted conditions. The server correctly blocks the mutation API, but the internal confirmation route itself is misleading and does not function according to the authenticated state.

- **FAIL — Recovery state is not synchronized after recovery actions, breaking pause/resume availability at the privacy step.**  
  `state` is loaded only once at startup and is not updated after `/api/recovery-verify` or `/api/password`. After resetting a password, `state.recoveryStage` still remains `"start"` in the client. Consequently, the recovery-specific “Pause and return later” button is omitted from the privacy screen, despite the server being at recovery stage `"privacy"`.

- **FAIL — Login/recovery throttling is bypassable via attacker-controlled headers.**  
  `requestKey()` includes `x-forwarded-for` and `origin`, both attacker-controlled on direct requests. An attacker can vary `X-Forwarded-For` and/or `Origin` to obtain a fresh throttle key for every attempt, defeating the intended brute-force protection. The comment says forwarded headers are not trusted, but the code still uses them as part of the throttling identity.

- **PASS — Calm, structured, low-distraction UX is substantially present.**  
  The UI uses a clear step sequence, progress bar, “Next” reminders, persistent help panel, safe-authentication advice, no countdowns, and pause/resume controls during much of recovery.

- **PASS — Browser-side simulated logs are implemented.**  
  Recovery delivery, MFA code availability, password replacement, and privacy acceptance use browser `console.log` through the `log()` function and are also shown in an on-page testing-log region.

## FAILING_ITEMS

- Client-side routing does not validate the current authenticated/recovery state before rendering sensitive routes. In particular, unauthenticated visitors can open `#/confirmation` and see a false success confirmation.
- Client state is stale after successful recovery verification and password replacement. This causes recovery-dependent UI decisions to be wrong, including the missing pause option on the recovery privacy screen.
- Brute-force/rate-limit controls are ineffective against attackers who vary `X-Forwarded-For` or `Origin` headers because those untrusted values are included in throttle keys.
- The UI does not consistently reload or update state after successful mutations, making refresh/direct-navigation behavior unreliable even where server-side authorization is correct.

## NEW_TASKS

1. Add a client-side route authorization function that checks the latest `/api/state` result before rendering protected routes:
   - Allow `/mfa` only when `mfaPending` is true.
   - Allow `/verify`, `/password`, and `/pause` only for the corresponding valid recovery stages.
   - Allow `/privacy` only for authenticated, MFA-verified/recovery-verified sessions.
   - Allow `/confirmation` only when `privacyAccepted` is true.
   - Redirect invalid routes to the appropriate valid next step with a clear status message.

2. Refresh or update `state` after every successful state-changing API call, especially `/api/recovery-request`, `/api/recovery-verify`, `/api/password`, `/api/mfa-verify`, `/api/privacy-accept`, `/api/pause`, and `/api/resume`. Use the updated recovery stage when rendering pause controls and progress-sensitive views.

3. Ensure the recovery privacy page always offers “Pause and return later” when the server reports an active recovery stage, including `"privacy"`.

4. Replace the throttle key design so it does not rely on attacker-controlled `Origin` or `X-Forwarded-For` headers. Use a trustworthy server-provided client address if Bun exposes one in the request context; otherwise use server-side account/session-based throttling with bounded global fallback limits. Do not permit arbitrary request headers to create new throttle partitions.

## DECISION

**FAIL**