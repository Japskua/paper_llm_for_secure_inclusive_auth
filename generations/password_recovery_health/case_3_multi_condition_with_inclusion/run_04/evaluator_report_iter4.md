## SUMMARY

The artifact is a single-file Bun HTTPS SPA with strong overall structure: server-side sessions, CSRF validation, CSP nonces, secure cookies, staged recovery, reset-token expiry/single use, password policy, MFA simulation, and an accessible low-distraction UI. However, the primary password-recovery flow is currently broken because the generated approved-channel authorization secret fails the server’s own token validation. A user therefore cannot pass step 2 and cannot reset a password.

## FUNCTIONAL_CHECK

- **FAIL — Password recovery flow can be completed end-to-end.**  
  The approved-channel authorization step cannot succeed. `/api/recovery/start` generates `randomToken(24)`, which produces a base64url token of approximately 32 characters. `/api/recovery/channel` validates the submitted value through `isToken`, which requires 40–100 characters (`/^[A-Za-z0-9_-]{40,100}$/`). Consequently, even the exact simulated authorization secret is rejected.

- **PASS — A reset code/link is available in the browser console and can be entered manually.**  
  Once the approved-channel step is passed, the client logs both the reset token and verification URL using browser-side `console.log`, and the UI supports manual code entry. This is implemented correctly in intent, but is unreachable due to the prior token-length defect.

- **PASS — Internal navigation is implemented.**  
  The simulated verification-link route (`/recovery/verify`), manual verification route, sign-in transition, MFA transition, privacy confirmation, help view, and restart actions are all represented and routed within the SPA/server.

- **PASS — The app is a single-file Bun application without a bundler or external frontend assets.**  
  The HTML, CSS, browser JavaScript, and Bun server are all contained in `app.ts`. Imported crypto functionality is from Node-compatible built-ins and does not require a build step.

- **PASS — Bun HTTPS and certificate usage are configured.**  
  The server checks for `certs/cert.pem` and `certs/key.pem`, fails closed when absent, and starts a TLS listener using those files.

- **PASS — CSRF protections are substantially implemented for state-changing requests.**  
  POST endpoints require a valid session, a per-session CSRF token, and an exact same-origin `Origin` header. Cookies use `SameSite=Strict`, `Secure`, and `HttpOnly`.

- **PASS — Reset tokens are random, hashed server-side, short-lived, and single-use.**  
  Reset tokens are generated with cryptographic randomness, only SHA-256 digests are stored in the session, expire after 15 minutes, and are invalidated after password reset.

- **PASS — Password policy and password hashing are implemented.**  
  The password policy requires 12+ characters, upper/lowercase, digit, symbol, and no spaces. Changed passwords are stored with `Bun.password.hash(..., { algorithm: "argon2id" })`, rather than plaintext.

- **PASS — Brute-force controls are implemented for recovery verification, channel confirmation, login, and MFA.**  
  The application limits attempts and applies a 10-minute lock period after repeated failures.

- **PASS — XSS defenses are appropriately used in the client UI.**  
  Client-side rendering uses DOM APIs and text nodes rather than assigning untrusted values through `innerHTML`. The CSP restricts scripts/styles to server-generated nonce-bearing content.

- **PASS — Security headers and restrictive CSP are configured.**  
  The server sets HSTS, CSP, `X-Content-Type-Options`, frame protections, `Referrer-Policy`, `Permissions-Policy`, and no-store caching headers.

- **PASS — ADHD/inclusivity-oriented UX is substantially addressed.**  
  The UI has visible step progress, concise “Next step” prompts, pause/return language, persistent server-backed state, help/safety guidance, large readable controls, focus handling, and no client-side timer pressure.

## FAILING_ITEMS

- **Approved-channel verification is impossible due to incompatible token generation and validation.**  
  `randomToken(24)` generates a token too short for `isToken()`. The user is shown and instructed to enter an authorization secret that the server will always reject.

- **The app therefore fails its core purpose: a valid user cannot complete password recovery and reach password reset, sign-in, MFA, and privacy acceptance through the normal flow.**

## NEW_TASKS

1. Make the approved-channel authorization secret conform to the validation rule: either generate it with at least 32 random bytes (for example, change `randomToken(24)` to `randomToken(32)`), or introduce a dedicated authorization-secret validator that accepts the actual generated length while preserving a strict base64url format.

2. Verify the complete happy path after the change: start recovery, submit the browser-logged authorization secret, open or manually submit the reset code, set a compliant password, sign in using that password, submit the MFA code, and accept the privacy statement.

## DECISION

**FAIL**