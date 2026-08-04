## SUMMARY

The artifact is a well-structured single-file Bun application with a mostly functional recovery flow, server-side sessions, per-session CSRF validation, throttling, bcrypt password hashing, MFA simulation, secure response headers, DOM-safe client rendering, and no external requests. However, it fails key security/functional requirements because the simulated recovery link is constructed with the wrong origin/port and therefore does not work on the configured HTTPS server, and because the application explicitly falls back to an unsecured HTTP server when certificates are absent.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no framework, bundler, compiler, or external assets.**
  - All server code, HTML, CSS, and browser JavaScript are contained in `app.ts`.
  - The implementation uses `Bun.serve` directly and does not make external network calls.

- **PASS — Recovery request UI and non-enumerating recovery response.**
  - The request screen accepts a constrained recovery identifier.
  - `/api/recovery` returns the same generic recovery message for all identifiers, preventing obvious account enumeration.
  - The generated test token is returned only for the exercise mock and is logged by browser-side JavaScript.

- **PASS — Manual recovery-code submission is supported.**
  - The verification screen provides a recovery-code input.
  - It accepts the URL `token` parameter and allows the same code to be entered manually.

- **FAIL — Recovery link functionality / internal navigation requirement.**
  - The browser logs the recovery link as:
    ```js
    "https://localhost/?token=" + deliveredToken
    ```
  - The configured TLS server runs on `HTTPS_PORT`, defaulting to `3000`. Therefore, when the app is served from `https://localhost:3000`, the generated link incorrectly points to HTTPS port `443`, where no server is configured.
  - This means the delivered recovery link does not function correctly under the default configuration.

- **PASS — Reset tokens are random, short-lived, session-bound, and single-use.**
  - Tokens are created using cryptographic randomness.
  - Tokens expire after 10 minutes.
  - Tokens are associated with the creating session.
  - Verification marks a token as used and rejects reuse.

- **PASS — Sensitive state-changing API routes require a per-session CSRF token.**
  - `/api/recovery`, `/api/verify-token`, `/api/password`, `/api/mfa`, `/api/privacy`, and `/api/login` all call `requireSessionAndCsrf`.
  - CSRF tokens are session-specific and checked with a timing-safe comparison.
  - The session cookie uses `HttpOnly`, `Secure`, and `SameSite=Strict`.

- **PASS — Access control and flow sequencing are server-enforced.**
  - Password creation requires verified recovery state.
  - MFA requires password replacement.
  - Privacy acceptance requires completed MFA.
  - Authorization is derived from server-side session flags rather than client-provided object identifiers.

- **PASS — Password policy and password storage meet the stated requirements.**
  - The password policy requires at least 12 characters, upper/lowercase letters, a number, a symbol, and no whitespace.
  - Passwords are hashed using bcrypt via `Bun.password.hash`.
  - Plaintext password values are not retained in server-side session state.

- **PASS — Brute-force throttling is implemented for recovery, token verification, MFA, and login placeholder routes.**
  - Recovery requests are limited to three per 15 minutes per session.
  - Token verification, MFA, and login attempts are rate limited.
  - Token verification additionally limits token attempts and invalidates exhausted tokens.

- **PASS — XSS protections are substantially implemented.**
  - User-controlled content is rendered through `textContent` and DOM APIs rather than `innerHTML`.
  - The client does not interpolate user inputs into HTML strings.
  - CSP uses per-response nonces for the trusted inline style and script blocks.
  - No untrusted scripts or external script sources are permitted.

- **FAIL — HTTPS is not enforced when TLS certificates are unavailable.**
  - If `certs/cert.pem` and `certs/key.pem` are missing, the application starts:
    ```ts
    Bun.serve({ port: HTTPS_PORT, fetch: handle });
    ```
  - This serves the full recovery portal over plain HTTP and prints a development HTTP URL.
  - The requirements explicitly state that HTTPS must be enforced and unsecured networks must not expose sessions. The application should fail closed rather than provide an insecure fallback.

- **PASS — TLS certificates are used when present, and HTTP redirects use a fixed allowlisted HTTPS host.**
  - When certificates exist, Bun is configured with `tls: { cert, key }`.
  - The HTTP listener redirects only to `https://localhost:${HTTPS_PORT}`, rather than trusting attacker-controlled host input.

- **PASS — Secure headers are broadly configured.**
  - HSTS, CSP, frame restrictions, MIME sniffing protection, referrer policy, permissions policy, COOP, CORP, and no-store cache directives are set.
  - API responses also receive the security-header set.

- **PASS — Safe-authentication guidance is presented.**
  - The UI tells users not to share passwords or security codes by email, phone, or text.
  - It advises users to verify the expected localhost HTTPS address.

- **FAIL — CSS contains a syntax error.**
  - The CSS declaration:
    ```css
    h1 { font-size:1.65rem; line-height:1.22; margin:0 0:12px; }
    ```
    is invalid because `margin:0 0:12px` is not valid CSS syntax.
  - The declaration will be ignored by browsers, resulting in unintended heading spacing.

## FAILING_ITEMS

- The simulated recovery link hardcodes `https://localhost/` and omits the configured HTTPS port. With the default server configuration, it points to port 443 instead of port 3000 and cannot complete the recovery flow.
- The missing-certificate fallback serves the application through plain HTTP. This violates the mandatory HTTPS enforcement requirement and exposes a security-sensitive recovery flow on an unsecured connection.
- The `h1` CSS `margin` declaration contains invalid syntax: `margin:0 0:12px;`.

## NEW_TASKS

1. Replace the hardcoded simulated recovery-link origin with the current browser origin, for example:
   ```js
   log("SIMULATED RECOVERY LINK: " + location.origin + location.pathname + "?token=" + encodeURIComponent(deliveredToken));
   ```
   This must preserve the active configured HTTPS port.

2. Remove the plain-HTTP development fallback. If TLS certificate files are unavailable, log a non-sensitive startup error and terminate or throw instead of serving the recovery portal insecurely.

3. Correct the invalid CSS declaration to valid syntax, for example:
   ```css
   h1 { font-size:1.65rem; line-height:1.22; margin:0 0 12px; }
   ```

## DECISION

FAIL