## SUMMARY

The artifact is a well-structured single-file Bun HTTPS SPA with a functional simulated recovery flow, CSRF validation, security headers, CSP nonces, Argon2id password hashing for updates, password policy enforcement, login throttling, MFA simulation, and accessible low-distraction UI. However, it does not fully satisfy the security and UX requirements: a caller who knows the account email can obtain a valid reset token directly from the API/UI, the initial password is embedded as plaintext in source code, persisted client progress can become inconsistent with expired/server-side recovery state, and the authenticated completion experience incorrectly returns to the “Password changed” screen rather than a distinct signed-in/privacy-confirmation state.

## FUNCTIONAL_CHECK

- **PASS — Single-file deliverable and zero-compilation operation**
  - The entire implementation is contained in `app.ts`.
  - Bun serves the HTML, CSS, inline client JavaScript, and API handlers directly.
  - Only Node built-in crypto imports are used; there are no frameworks, bundlers, external assets, or external network calls.

- **PASS — HTTPS server uses the supplied certificate paths**
  - The server checks for `certs/cert.pem` and `certs/key.pem`.
  - `Bun.serve()` is configured with TLS and listens on `localhost`.
  - It exits rather than silently falling back to insecure HTTP when certificates are absent.

- **PASS — Security headers and HTTPS protections**
  - HSTS, CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, and cache-control headers are configured.
  - Session cookies use `Secure`, `HttpOnly`, and `SameSite=Strict`.
  - CSP uses a per-response nonce for the controlled inline script and style block.

- **PASS — CSRF and same-origin controls**
  - State-changing API routes require POST.
  - Requests require an exact matching `Origin` header.
  - A per-session CSRF token is generated and validated with constant-time comparison.
  - CSRF validation is applied to recovery, password update, login, MFA, and logout routes.

- **PASS — XSS resistance and safe client rendering**
  - Dynamic UI strings are rendered with DOM construction and text nodes rather than `innerHTML`.
  - User input is not reflected into HTML markup.
  - The recovery-link token is URL encoded before insertion into a link.
  - CSP disallows untrusted script sources and external content.

- **PASS — Recovery flow, manual token entry, and recovery link**
  - The UI supports starting recovery, viewing simulated delivery information, opening a verification link, manually entering a code, choosing a new password, logging in, and completing MFA.
  - The reset token is shown in browser `console.log` and the in-page Logs panel as required for the simulated test environment.
  - The verification link route (`/recovery/verify?token=...`) is served by the SPA and can populate the verification step.

- **PASS — Reset tokens are random, hashed server-side, short-lived, and single-use**
  - Tokens are generated from `randomBytes(32)`.
  - Only SHA-256 token digests are stored in the session.
  - Tokens expire after 15 minutes.
  - Successful password reset invalidates the stored token data and marks the token used.

- **FAIL — Password reset flow prevents unauthorized account access**
  - `POST /api/recovery/start` returns the real reset token to any requester that submits the correct account email.
  - An attacker who knows or discovers the account email can create a session, receive a usable reset token, verify it, and set a new password without proving access to an approved recovery channel.
  - Returning simulated test tokens to the browser is required, but the implementation needs an explicit mock recovery-channel authorization model so the token is not sufficient by itself to reset a known account.

- **FAIL — Passwords are never stored in plaintext**
  - The initial password is embedded in source as plaintext:
    - `Bun.password.hash("Hospital!Safe2025", ...)`
  - Although the runtime account record stores the resulting Argon2id hash and updated passwords are hashed correctly, the plaintext credential is still present in the application source.

- **PASS — Strong password policy and password hashing for password updates**
  - New passwords require at least 12 characters, lowercase, uppercase, numeric, and symbol characters, with no spaces.
  - Passwords are stored with `Bun.password.hash(..., { algorithm: "argon2id" })`.
  - Passwords are verified with `Bun.password.verify`.
  - Password values are not logged.

- **PASS — Login and MFA brute-force mitigation**
  - Login attempts lock the email-derived key for 10 minutes after five failures.
  - MFA attempts are limited; after repeated failures the MFA stage cannot be completed.
  - Login errors are generic, reducing account/password enumeration through error messages.

- **PASS — MFA is implemented as a deterministic simulation**
  - Password login creates an MFA stage.
  - The deterministic MFA code is delivered through the browser Logs panel and `console.log`.
  - MFA must be validated before the server session reaches the `authenticated` stage.

- **FAIL — Pause-and-return UX remains reliable when state expires**
  - The UI restores `current` from `localStorage` without checking whether the server session is still at that stage or whether the reset token has expired.
  - For example, a user may return after 15 minutes and be placed directly on “Choose a new password,” despite the reset token no longer being valid.
  - Submitting then produces only a generic failure, which is disorienting and does not provide the clear recovery guidance required for users who may lose track of multi-step tasks.

- **FAIL — Authenticated completion state and privacy-statement goal are not correctly represented**
  - After successful MFA, the UI sets `current = "success"`.
  - `successView()` is a “Password changed” view that offers “Go to sign in,” even though the user has already signed in successfully.
  - There is no distinct authenticated confirmation screen or privacy-statement review/acceptance screen, despite the use case requiring Helena to access the account and accept updated privacy conditions.

- **PASS — Inclusive visual and interaction design**
  - The interface has visible progress, clear “Next step” instructions, a simple single-card layout, help links, safety guidance, generous typography, focus styles, and a skip link.
  - There are no visible countdowns or unexpected automatic route changes.
  - The interface avoids dense instructions and uses straightforward language.

## FAILING_ITEMS

- A valid reset token is returned to any requester who supplies the correct account email, enabling unauthorized password reset in the simulated environment.
- The initial account password is present as a plaintext literal in `app.ts`.
- `localStorage` can restore an invalid/stale client step after server session expiration or reset-token expiry, causing a confusing generic error instead of clear recovery guidance.
- Successful MFA reuses the password-reset success screen, incorrectly telling an authenticated user to sign in again.
- The flow does not include the required post-authentication privacy-statement review/acceptance outcome described by the use case.
- Minor code-quality issue: the CSS declaration `box-shadow:0 2px 8px #1231 11` is invalid and will be ignored by the browser.

## NEW_TASKS

1. Implement a mock approved-recovery-channel authorization step so a known email address alone cannot obtain a reset token that can reset the account; retain browser-console/UI token visibility only after that mock authorization succeeds.

2. Remove the hardcoded plaintext initial password from source and initialize the mock account from a precomputed Argon2id hash or a secure environment-provided hash.

3. Add a server-backed recovery-status endpoint or include recovery stage information in bootstrap; only restore saved client progress when it matches the active server session state.

4. When a reset token or recovery session has expired, clear stale recovery state and display a specific calm message with a single action to start a new recovery request.

5. Create a distinct authenticated completion view after MFA that confirms sign-in, presents the updated privacy statement, and provides an explicit acceptance action or simulated acceptance confirmation.

6. Correct the invalid `box-shadow` CSS declaration.

## DECISION

FAIL