## SUMMARY

The artifact is a single-file Bun/HTML/CSS/vanilla-JS password recovery SPA with TLS, security headers, CSRF validation, short-lived random reset tokens, bcrypt password hashing, simulated MFA, and browser-console mock delivery logs. Most required flow and security measures are implemented correctly. However, it has a password-reset authorization race condition that permits concurrent password-update requests to pass the one-time recovery authorization check, and the privacy screen does not display the actual updated privacy conditions before requiring acceptance.

## FUNCTIONAL_CHECK

- **Single `app.ts` file containing Bun server, HTML, CSS, and browser JS — PASS**
  - The supplied artifact is one TypeScript file and embeds all client HTML, CSS, and JavaScript. No framework, bundler, compilation step, or external asset is used.

- **Bun TLS server using provided certificate paths — PASS**
  - The server checks for `certs/cert.pem` and `certs/key.pem`, fails closed if unavailable, and starts Bun TLS with those files.
  - A separate HTTP listener performs a fixed-host `308` redirect to `https://localhost:<HTTPS_PORT>`.

- **HTTPS enforcement and secure response headers — PASS**
  - HTTPS is used for the portal, HTTP redirects to HTTPS, and the artifact configures HSTS, CSP, `X-Frame-Options`, `nosniff`, Referrer Policy, Permissions Policy, COOP, CORP, and no-store caching.

- **CSRF protection on sensitive requests — PASS**
  - Each session has a cryptographically random CSRF token.
  - All state-changing API endpoints (`/api/recovery`, `/api/verify-token`, `/api/password`, `/api/mfa`, `/api/privacy`, and `/api/login`) require and validate `X-CSRF-Token`.
  - Cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`.

- **Sensitive-route authorization and avoidance of private-identifier exposure — PASS**
  - Recovery state is held server-side in opaque session and token maps.
  - The UI does not render usernames, patient data, folders, account identifiers, or server-side internal details.
  - API responses are generic where account existence could otherwise be disclosed.

- **XSS/injection defenses — PASS**
  - User-controlled values are not interpolated into generated HTML.
  - The client uses `textContent`, DOM construction, and `replaceChildren` rather than `innerHTML`.
  - CSP uses per-response nonces for the trusted inline style and script blocks.
  - Request input is type-checked and constrained server-side.

- **Reset tokens are random, short-lived, and single-use — PASS**
  - Reset tokens are generated with cryptographic randomness, expire after 10 minutes, have bounded verification attempts, and are removed immediately after successful verification.
  - Token-link sessions are restricted until the token is POST-verified.
  - Manual recovery-code entry is supported in addition to the recovery-link route.

- **Recovery delivery and MFA delivery are simulated in the browser console — PASS**
  - The recovery token and recovery link are printed through browser-side `console.log`.
  - The deterministic MFA code is also logged in the browser.
  - The reset token is returned to the UI flow for local testing as required.

- **Strong password policy and bcrypt hashing — PASS**
  - Passwords require at least 12 non-space characters with lowercase, uppercase, numeric, and symbol characters.
  - Passwords are bcrypt-hashed with `Bun.password.hash(... algorithm: "bcrypt")`.
  - Plaintext passwords are not persisted in application state.

- **MFA and safe-authentication guidance — PASS**
  - The flow requires a six-digit MFA code after password replacement and before privacy-condition acceptance.
  - The UI includes anti-phishing guidance, including instructions not to share passwords or codes through email, phone, or text.

- **Brute-force throttling — PASS**
  - Recovery, token verification, MFA, and demonstration login routes implement request limits.
  - Token verification additionally has a server-side per-token attempt cap.

- **One-time password-reset authorization is safely consumed — FAIL**
  - `apiPassword` checks `session.resetVerified`, then awaits `Bun.password.hash(...)`, and only afterward sets `session.resetVerified = false`.
  - Two concurrent `/api/password` POST requests with the same valid session and CSRF token can both pass the authorization check before either request clears `resetVerified`.
  - This contradicts the code comment claiming that a second password POST is rejected and means recovery authorization is not atomically single-use.

- **Privacy conditions are shown before acceptance — FAIL**
  - The privacy screen contains only a short summary sentence and a checkbox stating “I have read and accept the updated privacy conditions.”
  - It does not actually render the updated privacy conditions/policy content that the user is supposed to read and accept.

- **Internal recovery-flow navigation — PASS**
  - The request, simulated delivery, token verification, password update, MFA, privacy acceptance, completion, restart, and token-link entry paths all function through browser-side UI transitions.
  - The recovery link correctly loads the verification screen, and manual code submission is available.

- **Production-safe error behavior — PASS**
  - Unexpected handler errors are converted to a generic message without stack traces or debug details.
  - Unknown routes return a non-debug 404 response.

## FAILING_ITEMS

- Password-reset authorization is vulnerable to a concurrent-request race:
  - `session.resetVerified` remains true while `await Bun.password.hash(...)` is in progress.
  - Concurrent requests can reuse the same verified reset authorization and both update `credentialHash`.
  - This violates the intended one-time recovery authorization behavior.

- The privacy acceptance UX does not provide the actual updated privacy conditions:
  - The user is asked to attest that they have read conditions that are not displayed.
  - This does not satisfy the stated goal of allowing Helena to review and accept updated privacy conditions.

## NEW_TASKS

1. Make reset authorization consumption atomic in `apiPassword`:
   - Immediately clear or transition `session.resetVerified` before awaiting password hashing.
   - Ensure a second concurrent password request is rejected.
   - If hashing fails, return a safe error; do not restore the consumed recovery authorization.

2. Add the actual updated privacy-condition content to `showPrivacy`:
   - Render a concise, readable privacy-policy section before the acceptance checkbox.
   - Keep the content static or create it with safe DOM APIs.
   - Retain the existing MFA-gated server-side acceptance check.

## DECISION

**FAIL**