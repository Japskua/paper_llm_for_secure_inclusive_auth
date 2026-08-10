## SUMMARY

The artifact is a single-file Bun/TypeScript SPA with a largely complete recovery flow, TLS configuration, CSRF validation, server-side session state, rate limiting, Argon2id hashing for reset passwords, MFA simulation, and accessible step-oriented UI. However, it does not fully meet the security requirements because it embeds a real usable initial account password in plaintext source code and uses that password to initialize the hash. This directly violates the requirement that passwords must never be stored in plaintext and creates an unauthorized-access risk for anyone with access to the artifact source.

## FUNCTIONAL_CHECK

- **PASS — Single-file application and zero-compilation approach**
  - All server code, HTML, CSS, and browser JavaScript are contained in `app.ts`.
  - The app uses Bun directly and does not require a bundler, framework, external assets, or external network calls.

- **PASS — Bun TLS server configuration**
  - `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`.
  - The startup URL uses `https://localhost`.

- **PASS — Structured, ADHD-friendly recovery UX**
  - The UI provides persistent visible progress, one primary step at a time, plain language, status messages, no countdown UI, help access, and server-resumable recovery state.
  - The recovery code may be entered manually or through the rendered recovery link.
  - The user can refresh and return to an in-progress recovery session without losing the server-side recovery state.

- **PASS — Simulated deliveries are visible in the browser console**
  - Recovery and MFA mock values are logged through browser-side `console.log`.
  - The recovery code is also surfaced in the demo Logs panel, satisfying the explicit testing requirement.

- **PASS — Recovery token generation, expiry, and single-use handling**
  - Reset codes are generated with cryptographically secure randomness.
  - They expire after 15 minutes.
  - Tokens are deleted synchronously during verification and converted into a separate short-lived, session-bound reset grant.

- **PASS — CSRF protections on sensitive requests**
  - A random CSRF token is generated per server-side session.
  - All `/api/*` POST requests require and validate the CSRF token.
  - Session cookies use `HttpOnly`, `Secure`, `SameSite=Strict`, and `Path=/`.

- **PASS — XSS-resistant client rendering**
  - User-controlled values are not inserted with `innerHTML`.
  - Dynamic UI content is rendered using `textContent`, `replaceChildren`, and explicitly created DOM nodes.
  - CSP uses per-response nonces for the inline application script and stylesheet.

- **PASS — Secure response headers and caching controls**
  - HSTS, CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, and `Cache-Control: no-store` are configured.
  - No directory listing, debug endpoint, external asset, or external redirect behavior is present.

- **PASS — Password policy and reset-password hashing**
  - Reset passwords require at least 12 characters with uppercase, lowercase, number, and symbol.
  - Password values are not trimmed or normalized.
  - Updated passwords are hashed using `Bun.password.hash(..., { algorithm: "argon2id" })`.

- **PASS — Brute-force mitigations and MFA**
  - Reset requests, recovery-token verification, login attempts, and MFA attempts have server-side rate limits.
  - The flow requires a simulated MFA code after password sign-in.
  - MFA codes expire after five minutes.

- **FAIL — Passwords are never stored in plaintext**
  - The source includes the plaintext password `"HelenaStrong!2025"`:
    ```ts
    passwordHash: await Bun.password.hash("HelenaStrong!2025", {
      algorithm: "argon2id",
    }),
    ```
  - Even though the stored account field contains a hash after initialization, the password itself is embedded in the source artifact and is therefore stored and exposed in plaintext.
  - Anyone who can inspect the supplied `app.ts` can use that known credential to authenticate as the mock account.

- **FAIL — Password reset/authentication flow prevents unauthorized access**
  - Because the plaintext password is visible in source and `/api/login` always validates against `helenaAccount.passwordHash`, an attacker with the source can authenticate as the account without completing recovery.
  - This is especially problematic because successful MFA then permits the sensitive privacy-statement action.

## FAILING_ITEMS

- The initial mock account password, `HelenaStrong!2025`, is hardcoded in plaintext in `app.ts`.
- The hardcoded password is usable through `/api/login`, making the mock account directly accessible to anyone able to read the source code.
- The login endpoint is hardwired to `helenaAccount` rather than being tied to the account context established by the recovery flow. This weakens account-context enforcement and makes the hardcoded credential issue directly exploitable.
- Browser API calls have no `try/catch` handling. If the server is unavailable, TLS fails, or a response is malformed, the UI can produce an unhandled promise rejection rather than clear, low-stress feedback.

## NEW_TASKS

1. Replace the plaintext initial password initialization with a precomputed Argon2id password-hash fixture; do not include the corresponding plaintext password anywhere in `app.ts`.
2. Remove the ability to authenticate a hardcoded global account solely from a source-known credential; bind post-reset sign-in to the server-side account context established by the verified reset flow, or implement a safe mock login identity flow that does not expose usable credentials in source.
3. Add browser-side `try/catch` handling around `initialize()` and all API actions so network, TLS, and JSON parsing failures display a clear actionable status message without losing the current visible step.

## DECISION

FAIL