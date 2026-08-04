## SUMMARY

The artifact is a valid single-file Bun application with a functional browser-based recovery flow, TLS configuration, CSP nonces, CSRF validation, token expiry, Argon2id hashing, and client-side safe rendering. However, it does not securely model identity ownership: any caller providing any syntactically valid email receives a usable reset token and the fixed MFA code, allowing that caller to reach an authenticated state. In addition, throttling is only per in-memory session and can be bypassed by starting new sessions. These issues fail the password-reset authorization and brute-force requirements.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun server and client application**
  - The server, HTML, CSS, and browser JavaScript are all contained in `app.ts`.
  - It uses Bun directly, with no framework, build tool, bundler, or external assets.

- **PASS — TLS is configured with the required certificate paths**
  - `Bun.serve()` uses `certs/cert.pem` and `certs/key.pem`.
  - The handler rejects non-HTTPS requests.

- **PASS — Recovery request, reset-link, and manual-token UX work**
  - The user can request a reset, open a generated internal reset link, or navigate to `#verify` and paste a token manually.
  - The reset token is returned to the browser and logged via browser-side `console.log`, as required for the simulation.

- **PASS — Internal navigation functions**
  - The simulated reset link routes to verification.
  - Hash routes for verification, privacy acceptance, and completion are handled.
  - Attempts to access privacy/completion screens are checked server-side through `/api/session-status`.

- **PASS — CSRF protections are present on sensitive state-changing requests**
  - A random CSRF token is generated per server session.
  - Sensitive `POST /api/...` routes require the `X-CSRF-Token` header.
  - The CSRF token is not stored in the cookie and the session cookie is `HttpOnly` and `SameSite=Strict`.

- **PASS — Session and reset-token implementation has several appropriate controls**
  - Sessions use random identifiers and secure cookie attributes.
  - Reset tokens are generated with cryptographic randomness, stored as SHA-256 hashes, session-bound, expiry-bound, and invalidated after password reset.
  - Privacy acceptance requires an authenticated session.

- **FAIL — Password reset flow prevents unauthorized access**
  - `/api/recovery/request` creates and returns a valid reset token for **every syntactically valid email address**, without confirming a simulated account or ownership of that account.
  - The MFA code is a globally fixed value (`246810`) and is returned to the requester after token verification.
  - Therefore, an attacker can submit a victim email address, receive a usable token in their own session, complete MFA with the known code, reset the simulated password, and become authenticated.

- **FAIL — MFA meaningfully verifies identity**
  - MFA is present as a UI/API step, but it is not tied to an independent enrolled factor or account-controlled channel.
  - Since the caller receives both the reset token and fixed MFA code in the same browser session, MFA does not add a meaningful ownership check.

- **FAIL — Automated abuse/brute-force attempts are effectively throttled or blocked**
  - Recovery, reset-token verification, and MFA limits are only stored on the current in-memory session.
  - An attacker can clear cookies, use another browser profile, or make requests without preserving cookies to obtain new sessions and reset the counters.
  - There is no IP-, account-, or token-associated rate limiting.

- **PASS — Password policy and password hashing**
  - The server enforces a 12-character minimum and upper-case, lower-case, number, and symbol requirements.
  - Passwords are passed to `Bun.password.hash(..., { algorithm: "argon2id" })` and are not stored in plaintext.
  - In this mock flow, the resulting hash is discarded, which is acceptable only because there is no real account/login store.

- **PASS — XSS/injection defenses in client rendering**
  - User-controlled values are not inserted through `innerHTML`.
  - Dynamic UI text uses `textContent`.
  - API inputs are type-checked and constrained before sensitive use.
  - The CSP uses a per-response nonce for the application’s inline script and style.

- **PASS — Security headers and no-cache policy**
  - HSTS, CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, Permissions Policy, COOP, CORP, and no-cache headers are configured.
  - The CSP prevents untrusted external scripts and restricts network connections to same-origin.

- **PASS — No external network calls, open redirects, or SSRF-capable URL handling**
  - Browser requests target same-origin API endpoints.
  - The reset link is a fixed relative internal path.
  - No user-provided URL is fetched or redirected to.

- **PASS — Safe-authentication guidance is provided**
  - The UI clearly tells users not to disclose passwords, reset tokens, or verification codes to staff/support callers.
  - The footer includes anti-phishing guidance.

- **PASS — Code is syntactically and structurally valid for Bun 1.3**
  - The used APIs (`Bun.serve`, `Bun.file`, `Bun.CryptoHasher`, and `Bun.password.hash` with `argon2id`) are appropriate for Bun.
  - No obvious TypeScript syntax errors or broken references are present.

## FAILING_ITEMS

- **Unauthorized reset/authentication is possible for arbitrary valid email addresses.**
  - The recovery endpoint does not look up a simulated account, check account ownership, or restrict which identity may receive a reset flow.
  - It returns `testToken` directly in the response for any valid email.
  - The subsequent MFA code is fixed and returned to that same requester.
  - This violates the requirement that password reset must prevent unauthorized access.

- **The MFA step is not an independent second factor.**
  - A fixed globally known code is not sufficient when the reset token is also issued directly to the requester for arbitrary emails.
  - The flow proves only possession of attacker-created session state, not possession of an account-controlled recovery factor.

- **Rate limiting is bypassable by creating new sessions.**
  - Counters are keyed only by session ID.
  - New sessions are trivial to create by omitting/clearing the session cookie.
  - This does not adequately throttle automated recovery, token, or MFA guessing/abuse.

## NEW_TASKS

1. Add a minimal in-memory simulated account/recovery identity model, using only non-sensitive test account identifiers, so recovery requests can be associated with a specific account without exposing account existence to the browser.

2. Change `/api/recovery/request` so it always returns the same generic browser response, but only creates a reset record for a recognized simulated account and binds that record to the intended account identity.

3. Model simulated reset delivery as an account-controlled channel: log the reset token in the browser only for the designated test account/session scenario, rather than returning a usable token for every submitted email address.

4. Replace the globally reusable MFA code with a per-reset-record code generated when the reset record is created; store only a hash of that code server-side and log the deterministic test delivery in the browser only for the authorized simulated recovery scenario.

5. Bind successful password reset to the account identity in the reset record, and persist that account’s Argon2id password hash in the in-memory test account store.

6. Add rate limits that cannot be reset simply by creating a new session, at minimum using a server-side key based on normalized email/account and a coarse client/IP key, while preserving generic responses to prevent account enumeration.

## DECISION

**FAIL**