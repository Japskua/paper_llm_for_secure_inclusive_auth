## SUMMARY

The artifact is a single `app.ts` Bun HTTPS application with a functional vanilla-JavaScript recovery flow: reset request, token-link/manual token verification, strong password replacement using bcrypt, MFA confirmation, privacy acceptance, and appointment confirmation. It correctly uses TLS certificates, session cookies, CSRF tokens, CSP nonces, security headers, and browser-side mock logging. However, it has material security failures: the HTTP redirect trusts the request host and can be used as an open redirect, recovery-token guessing is not actually rate-limited for arbitrary invalid guesses, and the global mock password can be reset by any browser session that submits any syntactically valid email address.

## FUNCTIONAL_CHECK

- **Single-file `app.ts` containing Bun server, HTML, CSS, and client-side JavaScript — PASS**
  - All server logic and client UI are contained in the supplied `app.ts`.
  - No framework, bundler, compilation pipeline, external script, stylesheet, or network asset is used.

- **Bun directly serves the application with TLS certificates from `certs/cert.pem` and `certs/key.pem` — PASS**
  - The HTTPS listener loads and uses both specified certificate files.
  - A separate HTTP listener redirects traffic to HTTPS.

- **Password-recovery UI and Helena’s recovery-to-appointment flow work — PASS**
  - The application supports recovery initiation, verification-link navigation, manual token entry, password update, MFA, privacy acceptance, and appointment confirmation.
  - Internal `/reset?token=...` navigation functions and manual recovery-token submission is available.

- **Mocks are logged in the browser and reset/MFA test values are accessible for testing — PASS**
  - The browser client uses `console.log`.
  - The reset token and deterministic MFA code are returned to the client and logged by the browser.
  - This complies with the explicit testing-mock requirement.

- **CSRF protection is implemented per session and checked on sensitive mutations — PASS**
  - Each session receives a cryptographically random CSRF token.
  - Sensitive `POST` API requests require the token.
  - Requests with an explicitly cross-origin `Origin` header are rejected.
  - The session cookie is `HttpOnly`, `Secure`, `SameSite=Strict`, and uses the `__Host-` prefix correctly.

- **Sensitive application actions enforce server-side authorization and avoid IDOR — PASS**
  - Privacy acceptance requires `authenticated`.
  - Appointment confirmation requires both authentication and privacy acceptance.
  - No user-supplied patient/account/appointment identifier is accepted by these routes.
  - State is scoped to the current server-side session.

- **XSS and injection protections are substantially implemented — PASS**
  - The application has a static HTML shell and constructs dynamic UI through DOM APIs.
  - Dynamic messages and log data are inserted through `textContent`, not `innerHTML`.
  - Passwords and tokens are never reflected into HTML.
  - CSP uses a per-page nonce for the trusted inline client script.
  - User input is validated before sensitive server-side use.

- **HTTPS/HSTS/security-header configuration — PASS**
  - HTTPS is served with the supplied TLS certificate.
  - HTTP is redirected using status `308`.
  - HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, COOP, CORP, and no-store caching are configured.

- **Password-reset tokens are random, bound to a session, short-lived, and eventually consumed — PARTIAL / FAIL**
  - Tokens are cryptographically random, SHA-256 hashed at rest, session-bound, and expire after 15 minutes.
  - However, a token is not consumed at successful verification; it remains reusable until the password-reset operation occurs. This does not strictly meet the requirement that reset tokens be single-use.
  - More importantly, arbitrary incorrect token guesses are not rate-limited or reliably counted.

- **Recovery verification and brute-force protection — FAIL**
  - Reset-request attempts are limited to three per session over ten minutes, and MFA attempts are limited to five.
  - But `/api/verify-reset` only increments `failedAttempts` when the supplied token hashes to an existing reset-token record belonging to that session.
  - Arbitrary invalid token guesses do not increment any counter and can be submitted indefinitely by a session possessing its CSRF token.
  - This does not satisfy the requirement that automated guessing attempts be throttled or blocked.

- **Passwords are securely hashed and strong-password rules are enforced — PASS**
  - Passwords are stored only via `Bun.password.hash` using bcrypt with cost 12.
  - The password is not retained in plaintext.
  - The server enforces a 12-character minimum plus lowercase, uppercase, digit, and symbol requirements.

- **MFA / additional authentication confirmation is implemented — PASS**
  - A password reset requires MFA confirmation before the session becomes authenticated.
  - MFA attempts are limited to five.
  - The deterministic mock code is suitable for the specified simulation.

- **Unauthorized password reset is prevented — FAIL**
  - Any syntactically valid email causes `/api/request-reset` to generate a valid reset token.
  - That token can reset the single global `mockPasswordHash`.
  - There is no account-email ownership check, account association, or other authorization condition before issuing a token that can alter the global password.
  - Therefore, any user/session can initiate and complete a password reset affecting the shared mock account.

- **No username/private identifier exposure — PASS**
  - The UI does not display an account name, patient data, course folder, or private identifier.
  - Generic recovery messaging is used.

- **SSRF/open-redirect protections — FAIL**
  - The plaintext HTTP redirect derives its destination host from `new URL(request.url).hostname`.
  - An attacker-controlled `Host` header can make the service issue a redirect to an arbitrary host, for example `https://attacker.example:3000/...`.
  - This is an open redirect and violates the outgoing-URL validation/whitelisting requirement.

- **Safe-authentication and anti-social-engineering guidance — PASS**
  - The interface explicitly tells users not to share passwords or verification codes.
  - It provides hospital-domain and link-safety guidance.
  - No staff-impersonation functionality or external support links exist.

- **No external network calls, debug stack traces, or directory listing exposure — PASS**
  - Client network calls are same-origin only.
  - Server responses use generic messages and do not expose stack traces.
  - No filesystem or directory-serving route exists.

- **Code validity / direct Bun execution — PASS, subject to required certificates being present**
  - The TypeScript and Bun APIs used are compatible with a direct Bun server implementation.
  - Startup necessarily depends on the specified certificate files being placed in `certs/`, as required.

## FAILING_ITEMS

- The HTTP-to-HTTPS redirect is an open redirect because it trusts the incoming request host:
  ```ts
  const host = url.hostname;
  const destination = `https://${host}:${HTTPS_PORT}${url.pathname}${url.search}`;
  ```
  A hostile `Host` header can produce a redirect to an attacker-controlled destination.

- Reset-token verification has no effective general brute-force limit.
  - Invalid guessed tokens do not increment a per-session failure counter unless the guessed token happens to match an existing token record.
  - This enables unlimited invalid token submissions.

- A reset token is not strictly single-use at verification time.
  - Successful calls to `/api/verify-reset` can be repeated until `/api/reset-password` is called.
  - The token should be consumed or exchanged for a separate, single-use, short-lived verified-reset capability.

- The password-reset flow does not validate that the requested email belongs to an account authorized for reset.
  - Every syntactically valid email receives a usable token.
  - Because `mockPasswordHash` is global, any session can replace it after requesting its own token.

## NEW_TASKS

1. Replace host-derived HTTP redirect construction with a fixed, configured, or strict allowlisted HTTPS host (for example, only `localhost`), and reject unexpected `Host` headers instead of redirecting to them.

2. Add a per-session reset-verification failure counter that increments for **every** invalid `/api/verify-reset` submission, locks/reset-invalidates the recovery flow after a small threshold, and returns `429` or an equivalent generic throttling response.

3. Make reset tokens strictly single-use by consuming the reset token immediately after successful verification and issuing a separate server-side, short-lived verified-reset grant for the password-update request.

4. Add a mock account-identity model that associates a non-exposed, server-side stored email hash with its password hash, and issue a usable reset token only when the submitted email matches that account. Preserve the same generic user-facing response for both matching and non-matching emails.

5. Ensure that a non-matching email does not return `testToken` and cannot lead to a password change; retain browser-console mock delivery only for the configured mock account/reset flow.

## DECISION

FAIL