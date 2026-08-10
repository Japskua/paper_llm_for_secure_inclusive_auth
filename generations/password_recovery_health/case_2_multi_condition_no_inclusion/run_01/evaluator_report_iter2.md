## SUMMARY

The artifact is a single-file Bun/TypeScript implementation with a functional recovery, reset, MFA, login, and privacy-acceptance flow. It has strong security coverage: HTTPS redirect, TLS configuration, secure cookies, CSRF validation, CSP nonces, server-side workflow checks, Argon2id password hashing, rate limiting, generic recovery messaging, and browser-console mock delivery. However, it does not fully meet the reset-token single-use requirement, and its CSP blocks JavaScript-applied inline styles used to reveal the simulated recovery-link control. Therefore, the artifact should not be accepted as fully compliant.

## FUNCTIONAL_CHECK

- **Single `app.ts` file contains Bun server, HTML, CSS, and vanilla browser JavaScript — PASS**
  - The supplied artifact is one file and includes both HTTPS/HTTP Bun servers plus the complete client application template and inline browser logic.
  - No framework, bundler, compiler, external asset, or network request is used.

- **Bun HTTPS server uses the supplied mkcert certificate paths — PASS**
  - The HTTPS server uses `certs/cert.pem` and `certs/key.pem` through:
    ```ts
    tls: { cert: Bun.file(CERT_PATH), key: Bun.file(KEY_PATH) }
    ```
  - The HTTP server redirects to HTTPS with status `308`.

- **Password recovery flow works, including manual reset-token submission — PASS**
  - Recovery accepts a tightly validated email or international phone format.
  - The token can be entered manually on `/reset`.
  - A token supplied through `/reset?token=...` is populated into the input.
  - Recovery token verification, recovery MFA, password replacement, login, login MFA, privacy acceptance, and confirmation are all wired to backend endpoints.

- **Mocks are delivered through browser `console.log` and deterministic test values — PASS**
  - The recovery token and deterministic MFA codes are logged by browser-side code using `console.log`.
  - The token/MFA values are not printed by server-side logging.
  - The deterministic values permit the academic flow to be tested.

- **CSRF protections are implemented for state-changing requests — PASS**
  - A random 64-character CSRF token is created per server-side session.
  - Browser API calls provide `X-CSRF-Token`.
  - Every state-changing `/api/*` request requires JSON plus a matching CSRF header.
  - Cookies use `Secure`, `HttpOnly`, `SameSite=Strict`, and the `__Host-` prefix.

- **Sensitive actions enforce server-side workflow/access controls — PASS**
  - Password replacement requires a verified token, matching reset session, unexpired record, unused record, and MFA verification.
  - Login MFA requires a preceding successful password verification.
  - Privacy acceptance requires authenticated session state.
  - The backend does not rely solely on client-side route navigation for authorization.

- **Recovery enumeration protection and brute-force throttling are present — PASS**
  - Recovery always returns a generic eligibility message, including for invalid contacts.
  - Token verification, recovery MFA, login, and login MFA are throttled.
  - Throttled actions are blocked for 60 seconds after their configured failure limits.

- **Passwords are hashed and a password policy is enforced — PASS**
  - New passwords are hashed with `Bun.password.hash(... { algorithm: "argon2id" })`.
  - No plaintext stored password is embedded in the artifact.
  - The server enforces 14–128 characters with lowercase, uppercase, number, symbol, and no spaces.

- **MFA is implemented for reset and login — PASS**
  - Recovery requires a second MFA code before a password can be changed.
  - Login also requires a separate MFA confirmation before the privacy statement is accessible.

- **XSS mitigation and safe DOM handling are implemented — PASS**
  - User-controlled values are not injected via `innerHTML`.
  - Client-generated messages use `textContent`.
  - The page uses a nonce-based CSP and does not load third-party scripts or assets.
  - The contact and token formats are server-side validated.

- **Security headers and production-safe error handling are present — PASS**
  - HSTS, CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, and `Cache-Control: no-store` are configured.
  - Server exceptions return a generic `503` response rather than stack traces.

- **Reset tokens are random and short-lived — PASS**
  - Tokens are generated from 32 random bytes (`64` hex characters).
  - Reset records expire after 10 minutes.
  - Reset records are bound to the creating session.

- **Reset tokens are single-use — FAIL**
  - A token is only marked `used = true` after the password has been successfully changed:
    ```ts
    record.used = true;
    ```
  - The `/api/reset/verify` endpoint allows the same valid token to be verified repeatedly prior to password submission.
  - This does not satisfy a strict “single-use” reset-token requirement. The token should be consumed at successful verification, with a separate server-side recovery authorization/MFA state retained for the remainder of the flow.

- **Simulated recovery verification link is reliably usable under the configured CSP — FAIL**
  - The recovery UI initially hides the test link with CSS:
    ```css
    .test-link { display:none; }
    ```
  - It attempts to reveal it with a JavaScript style attribute:
    ```js
    test.style.display = "inline-block";
    ```
  - The CSP allows only nonce-bearing style blocks:
    ```http
    style-src 'nonce-...'
    ```
  - CSP does not authorize dynamically applied `style=""` attributes. As a result, the browser may block the style assignment and the “Academic test: open simulated recovery link” remains hidden.
  - Manual token entry remains available, but the explicit simulated recovery-link path is not reliably functional.

## FAILING_ITEMS

- Reset records are reusable between successful token verification and password replacement, so reset tokens are not strictly single-use.
- The test recovery-link reveal relies on a style attribute assignment that is blocked by the artifact’s own strict CSP.
- The source includes additional dynamic style attribute assignments for the privacy checkbox:
  ```js
  check.style.width = "auto";
  check.style.marginRight = ".5rem";
  ```
  These are also incompatible with the nonce-only `style-src` policy, though they are primarily visual rather than flow-breaking.

## NEW_TASKS

1. Modify `/api/reset/verify` so a successfully verified reset token is immediately consumed and cannot be submitted again; retain only the necessary server-side, session-bound recovery/MFA authorization state for `/api/mfa` and `/api/password`.

2. Replace `test.style.display = "inline-block"` with a CSP-compatible class-based mechanism. Add a CSS class inside the nonce-bearing stylesheet, such as `.test-link.is-visible { display:inline-block; }`, and reveal the link using `test.classList.add("is-visible")`.

3. Replace `check.style.width` and `check.style.marginRight` with a predefined CSS class applied to the checkbox, avoiding style-attribute mutations under the strict CSP.

## DECISION

FAIL