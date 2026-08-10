## SUMMARY

The artifact is a single `app.ts` Bun HTTPS server with an inline vanilla-JS SPA and implements most of the intended recovery stages, CSRF checks, password hashing, reset-token expiry, MFA simulation, and accessible low-distraction UI. However, it contains a critical CSP nonce defect that blocks the entire client script from running in the browser, making the SPA non-functional. It also has rate-limit bypass and server-side session-expiration weaknesses. Therefore, it cannot be accepted.

## FUNCTIONAL_CHECK

- **Single-file Bun server with HTML, CSS, and vanilla JavaScript — PASS**
  - The application, server logic, HTML template, CSS, and browser-side JavaScript are all contained in `app.ts`.
  - No frameworks, build tools, bundlers, or external assets are used.

- **Bun HTTPS server using supplied certificates — PASS**
  - The server checks for `certs/cert.pem` and `certs/key.pem` and configures Bun TLS with them.
  - It does not fall back to insecure HTTP.

- **Password-recovery flow is usable in the browser — FAIL**
  - The root handler calls:
    ```ts
    return html(page(randomToken(16)), randomToken(16), cookie);
    ```
  - `page()` inserts the first nonce into:
    ```html
    <script nonce="...">
    ```
  - `html()` sets the CSP using the second, different nonce.
  - As a result, the browser blocks the only application script under CSP. Bootstrap, forms, progress tracking, recovery, token verification, MFA, password update, sign-in, and privacy acceptance never run.

- **Recovery token is random, session-bound, single-use, and short-lived — PASS**
  - Tokens use `randomBytes(32)`, are 64 hex characters, are bound to `current.session.recovery`, expire after 15 minutes, and are invalidated after password update.

- **Manual reset-token submission and deterministic mock delivery — PASS**
  - The UI accepts manual entry of the 64-character token.
  - The test token is returned in `testDeliveryToken` and logged by the client to the browser console and on-page Logs panel.
  - MFA is deterministic (`481516`) and is manually enterable.

- **Password policy and password hashing — PASS**
  - New passwords require at least 12 characters and uppercase, lowercase, digit, and symbol.
  - Passwords are stored with `Bun.password.hash(... bcrypt ...)`, not plaintext.

- **CSRF protection on sensitive POST endpoints — PASS**
  - A random CSRF token is created per session.
  - Sensitive POST routes require the `X-CSRF-Token` header and validate it with timing-safe comparison.
  - Cookies are `Secure`, `HttpOnly`, `SameSite=Strict`, and scoped to `/`.

- **XSS/input safety — PASS**
  - Client rendering uses DOM APIs and `textContent`, rather than injecting untrusted values through `innerHTML`.
  - API input is type-checked and constrained.
  - CSP is restrictive in intent, but currently prevents the app script from executing because of the nonce defect.

- **Security headers and HTTPS enforcement — PASS**
  - HSTS, CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, and no-store cache controls are configured.
  - The server is configured only with TLS.

- **Brute-force protection / throttling — FAIL**
  - Rate-limit keys include the session ID:
    ```ts
    return `${action}:${sessionId || ip}:${ip}`;
    ```
  - Every request has a session because all POST routes require `protectedSession()`.
  - An attacker can create a fresh session and obtain a new five-attempt allowance repeatedly, bypassing throttling.
  - The code also trusts the client-controlled `X-Forwarded-For` header without establishing that a trusted reverse proxy sets it, enabling further rate-limit key spoofing.

- **Server-side session lifetime enforcement — FAIL**
  - `createdAt` and `SESSION_AGE_SECONDS` are defined, but server-side sessions are never expired or removed.
  - Cookie expiration does not invalidate the corresponding server-side session. A copied session cookie can remain usable by directly sending it after its browser cookie lifetime should have ended.
  - Sensitive authenticated actions should reject expired sessions server-side.

- **Forgiving, structured, ADHD-supportive UX — FAIL**
  - The intended UX is well structured: visible steps, concise language, help content, no countdowns, progress persistence, and calm feedback.
  - However, because the CSP nonce mismatch blocks the client script, none of this UI behavior functions in an actual browser.

- **Mocks logged in the browser console — PARTIAL / FAIL**
  - The browser script does log simulated delivery and verification events.
  - However, the server also performs simulation logs through server-side `console.log`, such as:
    ```ts
    console.log("[delivery simulation] Recovery token issued to browser console.");
    ```
  - The requirement explicitly states that all mocks must use `console.log` **in the browser**. Server-side mock logging should be removed or limited to non-mock operational startup messages.

## FAILING_ITEMS

- The CSP nonce used in the HTML script element differs from the nonce included in the `Content-Security-Policy` header. This blocks all browser-side JavaScript and makes the SPA unusable.
- Rate limiting is per session rather than reliably per client/account/action, so an attacker can evade the five-attempt limit by creating new sessions.
- `X-Forwarded-For` is trusted directly even though no trusted proxy configuration exists, allowing attackers to spoof apparent client IP addresses for rate limiting.
- Server-side sessions have no enforced expiration despite having `createdAt` and `SESSION_AGE_SECONDS`; session records remain valid indefinitely unless manually removed.
- Mock delivery/verification events are logged on the server as well as in the browser, contrary to the requirement that mocks use browser `console.log`.

## NEW_TASKS

1. Generate one CSP nonce per root-page response, pass that exact nonce to both `page(nonce)` and `html(body, nonce, cookie)`, and remove the unreachable duplicate root-route condition.
2. Implement an expiring-session check in `findSession()` or `protectedSession()` using `createdAt` and `SESSION_AGE_SECONDS`; delete expired sessions and reject requests using them.
3. Redesign rate-limit keys so repeated attempts cannot be bypassed by obtaining a new session; limit sensitive actions by a trustworthy client identity and, where applicable, the protected account/recovery context.
4. Do not trust arbitrary `X-Forwarded-For` values unless the deployment explicitly uses a trusted proxy; otherwise use a server-provided peer address mechanism or a conservative shared rate-limit key for this local Bun deployment.
5. Remove server-side `console.log` calls for simulated delivery and verification events; retain browser-side logging of deterministic test values and client-facing simulation status.
6. Validate the corrected app in a browser with CSP enforcement enabled and confirm that bootstrap, recovery request, manual token verification, password update, MFA, login, and privacy acceptance all execute successfully.

## DECISION

**FAIL**