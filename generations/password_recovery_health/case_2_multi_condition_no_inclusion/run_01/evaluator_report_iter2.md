## SUMMARY

The artifact is a well-structured single-file Bun application with functional recovery, reset, MFA, login, and privacy-acceptance flows. It uses TLS, secure cookies, CSRF tokens, CSP nonces, bcrypt password hashing, server-side authorization checks, throttling, and browser-side mock-delivery logs. However, it does not fully meet the security requirements because its recovery API leaks account existence and provides an actionable reset token to anyone who submits the demo account identifier. It also uses an inline browser `<script>`, contrary to the explicit requirement that inline scripts are not allowed.

## FUNCTIONAL_CHECK

- **1. Broken Access Control — FAIL**
  - **CSRF protection:** PASS. Sessions receive unique random CSRF values, and all state-changing API routes validate `X-CSRF-Token` against the session token using constant-time comparison.
  - **Sensitive authorization / IDOR:** PASS. Password resets are bound to server-side session recovery authorization; privacy acceptance derives the account only from the authenticated session.
  - **No exposure of usernames/private identifiers:** FAIL. `POST /api/recovery/request` returns `testCode` and `resetPath` only when the submitted identifier resolves to the demo account. This gives a requester a direct account-existence oracle and exposes an actionable recovery secret based only on knowledge of an identifier.

- **2. Injection (XSS) — FAIL**
  - Input validation and safe output handling are generally strong: user input is not reflected into HTML, dynamic mock content is inserted with `textContent`, and the CSRF bootstrap escapes `<`.
  - However, the generated page includes an inline `<script nonce="...">` block. The requirements explicitly state that inline scripts are not allowed. A nonce makes the script CSP-authorized, but it does not make it non-inline.

- **3. Security Misconfiguration — PASS**
  - Bun is configured with the required TLS certificate and key files.
  - Application requests are rejected unless `url.protocol === "https:"`.
  - HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, permissions policy, no-store cache controls, and COOP are configured.
  - Session cookies are `Secure`, `HttpOnly`, `SameSite=Strict`, and use the `__Host-` prefix correctly.
  - Recovery tokens are random, session-bound, single-use, and expire after ten minutes.
  - Error responses do not expose stack traces or debug details.

- **4. Identification and Authentication Failures — FAIL**
  - **Password hashing:** PASS. Passwords are stored as bcrypt hashes using `Bun.password.hash(..., { algorithm: "bcrypt" })`.
  - **Strong password policy:** PASS. The server enforces length, upper/lowercase, numeric, and symbol requirements.
  - **MFA:** PASS for the simulation. MFA is required after password reset and login, and the mock MFA code is logged in the browser.
  - **Rate limiting:** PASS. Recovery, recovery verification, reset, login, and MFA routes have server-side IP/account/identifier-aware throttling.
  - **Unauthorized password reset prevention:** FAIL. An unauthenticated requester who knows the demo identifier can request recovery, receive the reset token in the API response/browser logs, verify it, choose a new password, receive the deterministic MFA code, and authenticate. The code comment calling a successful account lookup an “authorized demonstration account path” is incorrect; account lookup is not authorization.

- **5. SSRF and Social Engineering — PASS**
  - The server makes no outgoing network requests and accepts no external URL destinations, so SSRF and open redirects are not present.
  - The UI includes anti-phishing guidance instructing users not to share passwords or verification codes and to use only the local portal.
  - Recovery links are local relative paths and are not supplied by user-controlled URL input.

- **Single-file + zero-compilation compliance — PASS**
  - The server, HTML, CSS, and browser JavaScript are contained in one `app.ts` file.
  - The implementation uses Bun directly and does not depend on frameworks, bundlers, external assets, or external network calls.

- **Code validity / runtime error review — PASS**
  - The TypeScript structure is valid for Bun’s runtime model.
  - `Bun.serve`, TLS file usage, `Bun.password.hash/verify`, request handling, session storage, and browser event handlers are internally consistent.
  - No obvious syntax or control-flow error prevents the primary flows from operating.

## FAILING_ITEMS

- The recovery-request response is distinguishable for a real account:
  - Known/valid demo identifier: returns `testCode` and `resetPath`.
  - Unknown identifier: returns only a generic message.
  - This permits account enumeration and violates the requirement not to expose private account information.

- The same recovery-response behavior permits unauthorized account takeover in the provided application:
  - No proof of control over an email address, existing session, or other authenticated recovery factor is required before issuing the reset secret.
  - The reset token and deterministic MFA code are available to the unauthenticated requester through the UI/browser console.

- The page uses an inline browser script:
  - `<script nonce="${nonce}"> ... </script>` remains inline even though it is nonce-authorized.
  - This does not satisfy the explicit “No inline ... scripts are allowed” requirement.

## NEW_TASKS

1. Redesign the simulated recovery delivery so unauthenticated submission of an identifier cannot reveal whether an account exists or grant an actionable reset token for that account. Keep the generic response identical for all valid identifiers.

2. Preserve evaluator-visible mock delivery without making it an account-enumeration or takeover mechanism. Use a clearly isolated non-patient demonstration flow or a server-side test mechanism that does not issue a real account’s password-reset authority solely from a submitted identifier.

3. Move the browser JavaScript from the inline `<script>` block to a same-origin JavaScript route served by the same `app.ts` file, such as `/assets/app.js`. Pass the CSRF bootstrap value through a safely encoded HTML data attribute or a server-generated JSON endpoint, and update CSP to permit only the intended same-origin script.

## DECISION

**FAIL**