## SUMMARY

The artifact is a well-structured single-file Bun application with strong server-side controls for sessions, CSRF, token handling, password hashing, MFA simulation, throttling, and access checks. However, it has a critical CSP nonce defect: the nonce embedded in the HTML `<style>` and `<script>` tags differs from the nonce supplied in the response’s `Content-Security-Policy` header. Browsers will therefore block both the client script and stylesheet. The SPA renders an empty recovery screen and all recovery/login interactivity fails.

## FUNCTIONAL_CHECK

- **Single-file `app.ts` implementation using Bun, inline HTML/CSS/vanilla JS, and no external assets — PASS**
  - The server, HTML template, CSS, and browser-side JavaScript are all contained in `app.ts`.
  - No frameworks, build tools, external scripts, external stylesheets, or network integrations are used.
  - Bun TLS configuration references `certs/cert.pem` and `certs/key.pem`.

- **HTTPS and secure response headers are configured — FAIL**
  - TLS is configured and the application sets HSTS, CSP, `X-Content-Type-Options`, frame protection, referrer policy, permissions policy, and no-cache headers.
  - However, the CSP nonce in the HTTP response header does not match the nonce on the HTML’s inline `<style>` and `<script>` tags. This makes the CSP configuration non-functional for the page and blocks required client behavior.

- **Client UI and password recovery flow work directly in the browser — FAIL**
  - The browser-side script is blocked by CSP, so `recoveryView()` never runs.
  - The `#screen` section remains empty.
  - Form handlers, API calls, recovery-code entry, MFA entry, password reset, login, privacy acceptance, logout, URL-token handling, and simulated logs do not function.

- **Recovery token delivery simulation, browser console logging, reset-link flow, and manual token entry — FAIL**
  - The server correctly returns a testing-only `mockToken`.
  - The intended browser script would log the token and reset link to the browser console and render it in the Logs panel.
  - Because the script is blocked, no simulated delivery log appears, no reset link is presented, and manual submission cannot be performed through the UI.

- **CSRF protections for state-changing requests — PASS**
  - Sessions contain per-session random CSRF tokens.
  - Every `/api/*` POST route passes through `validCsrf`.
  - Validation requires both a matching `Origin` header and matching `X-CSRF-Token`.
  - Session cookies use `Secure`, `HttpOnly`, and `SameSite=Strict`.

- **Access control and IDOR prevention — PASS**
  - Sensitive operations use server-side session state and do not accept a client-controlled account identifier.
  - Privacy acceptance and portal access require the authenticated account ID in the session.
  - Reset records are bound to the session that successfully claims them.

- **XSS and injection protections — PASS**
  - User-provided values are not interpolated into server-rendered HTML.
  - Client-provided data is sent as JSON and UI log output uses `textContent`, not `innerHTML`.
  - Dynamic `innerHTML` content is static application markup, not derived from user input.
  - CSP is restrictive, although its nonce mismatch currently blocks legitimate script/style execution.

- **Secure reset-token handling — PASS**
  - Reset tokens are generated with cryptographically secure random bytes.
  - Only SHA-256 hashes of tokens are retained server-side.
  - Tokens expire after 15 minutes, are claimed by one session, and become single-use after password update.
  - Reset-token verification and MFA attempts are throttled.

- **Password security, login protection, and MFA — PASS**
  - Passwords are stored using bcrypt via `Bun.password.hash`.
  - A strong password policy is enforced: at least 12 characters with uppercase, lowercase, number, and symbol.
  - Login attempts are throttled per session and failed account login attempts result in temporary account lockout.
  - The recovery flow includes simulated MFA verification with a deterministic mock value.

- **Privacy-safe UX and phishing/social-engineering guidance — FAIL**
  - The static safe-authentication notice is present in the raw HTML.
  - However, the primary recovery UI is never rendered due to the CSP error, so the required accessible recovery experience is unavailable.

- **No external calls, exposed private data, debug traces, or directory listings — PASS**
  - There are no outgoing network calls.
  - The app exposes no patient records, usernames beyond the testing account’s internal server-side mock, course folders, or private identifiers in the UI.
  - The server returns generic errors rather than stack traces.

## FAILING_ITEMS

- **CSP nonce mismatch blocks the entire SPA.**
  - `page(session)` generates its own nonce for `<style nonce="...">` and `<script nonce="...">`.
  - The GET handler separately calls `securityHeaders(randomToken(16))`, creating a different nonce for the `Content-Security-Policy` header.
  - Since CSP requires the header nonce to match the tag nonce, browsers block the inline stylesheet and script.

- **The recovery screen is blank and all browser interactivity is disabled.**
  - The page contains only an initially empty `<section id="screen">`.
  - Rendering depends on the blocked inline script calling `recoveryView()`.
  - Consequently, the user cannot request a recovery code, verify it, complete MFA, reset a password, log in, or accept privacy conditions.

- **Required browser-side simulated delivery logs do not occur.**
  - Token and reset-link logging is implemented in the blocked script.
  - The required browser `console.log` output and visible Logs panel entries are therefore unavailable.

## NEW_TASKS

1. Generate one CSP nonce per HTML page response and use that exact same nonce both:
   - in the response `Content-Security-Policy` header, and
   - in the HTML `<style nonce="...">` and `<script nonce="...">` attributes.

2. Refactor `page()` to accept the already-generated nonce, for example `page(session, nonce)`, and remove its internally generated unused `headers` value.

3. Update the GET `/` and `/reset` response creation so it generates one nonce, calls `page(session, nonce)`, and supplies `securityHeaders(nonce)` to `new Response(...)`.

4. Manually verify in a browser that no CSP violation blocks the page script or stylesheet, and that the recovery screen, browser-console simulated delivery logs, manual code verification, MFA, password update, login, privacy acceptance, and logout all work.

## DECISION

**FAIL**