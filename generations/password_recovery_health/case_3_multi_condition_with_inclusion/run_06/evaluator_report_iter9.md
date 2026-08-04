## SUMMARY

The artifact is a well-structured single-file Bun application with a functional recovery, MFA, password-change, login, and privacy-acceptance flow. It correctly uses HTTPS, CSP, session-bound CSRF tokens, bcrypt hashing for changed passwords, throttling, fixed internal routes, and browser-side mock-token logging. However, it does not fully meet the password-storage security requirement because the initial seeded password is reversibly embedded in source code via character codes rather than stored solely as a bcrypt hash. The recovery UI also claims that phone numbers can be used even though the backend only recognizes the fixed email recovery channel.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun server, UI, and client logic**
  - `app.ts` contains the Bun server, TLS setup, HTML template, CSS, and browser JavaScript. There are no frameworks, bundlers, external assets, or external network calls.

- **PASS — HTTPS enforcement and TLS certificate usage**
  - The HTTPS server reads `certs/cert.pem` and `certs/key.pem`.
  - The HTTP server redirects all requests to the fixed HTTPS localhost URL with a `308` response.
  - HTTPS responses include HSTS and other relevant security headers.

- **PASS — Secure headers and CSP**
  - The app sets HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and no-store cache headers.
  - The CSP permits scripts only from the same-origin `/app.js` resource and does not permit inline scripts.

- **PASS — CSRF protection**
  - Sessions receive a cryptographically random CSRF token.
  - Sensitive POST endpoints use `guarded()` and require the session-specific `X-CSRF-Token`.
  - The session cookie is `HttpOnly`, `Secure`, and `SameSite=Strict`.

- **PASS — Access control and IDOR protection**
  - Account IDs are server-side only and are never accepted from browser requests.
  - Password reset, MFA, password change, privacy acceptance, and logout are all bound to the current server session.
  - The privacy endpoint requires an authenticated session.

- **PASS — Reset token security**
  - Reset tokens are generated using `randomBytes`, are 32 bytes encoded as Base64URL, expire after 15 minutes, are session-bound, and become unusable after password change.
  - Requesting another recovery code replaces the active token, making the prior token unusable.

- **PASS — Manual recovery-code submission and simulated-link behavior**
  - The reset token is returned in simulation mode, logged in the browser console, and can be entered manually.
  - The “Open simulated recovery link” button correctly populates the recovery-code field and stays within the same secure SPA.

- **PASS — MFA and verification flow**
  - The recovery sequence requires reset-token verification followed by MFA verification before a password can be changed.
  - The deterministic MFA mock code is returned only after a verified reset token and is logged in the browser for testing.

- **PASS — Brute-force and issuance throttling**
  - Reset verification, MFA verification, and login failures are rate-limited and locked after repeated failures.
  - Recovery-code and MFA-code issuance are also throttled.

- **FAIL — Passwords are not exclusively stored as hashes**
  - Although changed passwords are bcrypt-hashed, the initial credential is reversibly embedded in the source code:
    ```ts
    String.fromCharCode(77, 101, 100, 82, 101, 118, 105, 101, 119, 33, 55, 50, 57, 52, 65, 120)
    ```
  - This is obfuscation, not secure password storage. Anyone with source access can reconstruct the initial password and sign in without using password recovery.
  - This violates the requirement that passwords must be hashed and never stored in plaintext.

- **PASS — Strong password policy**
  - New passwords require at least 12 characters, upper- and lowercase letters, a digit, a symbol, and no whitespace.
  - Password fields are cleared after submission.

- **PASS — XSS protection**
  - User-provided values are not inserted using `innerHTML`.
  - Status and log content use `textContent`.
  - API responses are JSON and do not reflect arbitrary user input.
  - Same-origin CSP limits script execution.

- **PASS — No open redirects or user-controlled outbound URLs**
  - Client navigation uses fixed local routes only.
  - The HTTP redirect target is fixed to `https://localhost:3443`.
  - No browser input is used as a redirect or outbound URL.

- **PASS — ADHD/inclusivity-oriented UX**
  - The flow includes five visible progress steps, orientation text, clear next-step messaging, accessible live status messages, help reminders, and no client-side countdown or automatic navigation.
  - Recovery state is restored from the server session after refresh/navigation, allowing users to pause and return.

- **FAIL — Recovery contact UI does not match backend capability**
  - The UI tells users: “Enter your email address or phone number.”
  - The backend only recognizes the one configured email address:
    ```ts
    account.recoveryChannel === contact
    ```
  - No phone number can match an account. This creates misleading guidance and can make users think their valid phone number should work when it cannot.

## FAILING_ITEMS

- The initial account password is reconstructable from source code through `String.fromCharCode(...)`. This is reversible plaintext storage/obfuscation, not bcrypt-only password storage.
- The recovery request form advertises phone-number recovery, but the server supports only the configured email recovery channel.

## NEW_TASKS

1. Replace the reversible `String.fromCharCode(...)` seeded credential with a precomputed bcrypt hash literal assigned directly to `demoAccount.passwordHash`; do not retain any recoverable initial password value in source code, logs, API responses, or browser JavaScript.

2. Make recovery-contact support consistent:
   - Either change the UI and labels to state that only the registered email address can be entered, or
   - Add a server-side normalized phone recovery channel to the account mock and safely match supported phone input without exposing account existence.

## DECISION

FAIL