SUMMARY:
The single-file Bun app implements a secure password recovery and login flow with MFA. It adheres to the no-external-assets constraint, serves HTTPS with HSTS and CSP, prevents CSRF with per-session tokens, hashes passwords with Argon2id, rate-limits sensitive actions, and logs simulated delivery data to the browser console. UI is semantic and hash-routed. However, there is a functional bug: after logging out, subsequent API calls fail CSRF because the client’s CSRF token isn’t refreshed, requiring a full page reload to proceed.

FUNCTIONAL_CHECK:
- Single-file Bun server + Client UI in one file (app.ts): PASS — All server, HTML, CSS, and client JS exist in app.ts. /app.js is served from in-file string.
- HTTPS enforced using mkcert certs; HTTP redirects to HTTPS: PASS — TLS configured with certs/cert.pem and certs/key.pem; HTTP 301 to https://localhost:3443.
- Interactivity works in browser as SPA: FAIL — After logout, the CSRF meta token becomes stale, causing all subsequent POSTs (e.g., login) to fail with “Invalid CSRF token” unless the page is reloaded.
- CSRF protection (unique per session; validated on sensitive requests): PASS — Per-session token stored server-side; all POST /api/* endpoints validate x-csrf-token; cookies are HttpOnly, Secure, SameSite=Strict.
- No user enumeration / Broken Access Control: PASS — Generic responses; no exposure of identifiers; no IDORs; sensitive actions don’t take user IDs from client.
- Injection (XSS) mitigations: PASS — No inline scripts; CSP script-src 'self'; client uses textContent; server escapes/normalizes inputs; no HTML injection.
- “Framework-level auto-escaping”: PASS (equivalent) — Although frameworks are disallowed, robust manual escaping plus CSP and innerText/textContent are used throughout.
- Security headers (HSTS, CSP, XFO, XCTO, Referrer-Policy, Permissions-Policy): PASS — Present and strict; HTML/JS responses set appropriate headers.
- Password reset tokens (random, single-use, short-lived): PASS — Random 24-byte, 10-minute TTL, must be verified, single-use enforced.
- Debug info off in production responses: PASS — Generic error handling; no stack traces in JSON.
- Weak HTTPS/session leakage: PASS — HTTPS only, HSTS, HttpOnly+Secure+SameSite=Strict cookie.
- Password reset links not predictable/interceptable: PASS — Strong randomness; transport is HTTPS; for demo returned to client for logging only.
- Identification & Authentication: PASS — MFA implemented; strong password policy enforced; Argon2id hashing; generic auth messages.
- Throttling/anti-bruteforce: PASS — Rate limits on login, reset request, and code verification endpoints with backoff.
- Reset flow validates tokens and provides clear feedback: PASS — Requires verified, unexpired token to set password; good error messages.
- SSRF/open redirects: PASS — No outgoing URL fetches; hash-based internal routing; HTTP→HTTPS redirect is local-only.
- Social engineering guidance: PASS — Prominent banner instructs safe practices.
- Internal navigation works (login, forgot password, enter code, reset password, MFA, confirmation): PASS — Hash router covers all views; manual code entry supported.
- Mocks via console.log in the browser (token and MFA code): PASS — Token and MFA code are logged in the UI Logs panel through console.log mirroring.
- No external network calls/build tools: PASS — All assets are served by the Bun server; no external fetches.

FAILING_ITEMS:
- CSRF meta token not refreshed after logout. Steps to reproduce: click Logout, then attempt to log in without reloading the page. The server creates a new session (and new CSRF token), but the client continues sending the stale CSRF token from the original meta tag, resulting in “Invalid CSRF token” on subsequent API calls. This breaks post-logout interactivity until a manual full page refresh.

NEW_TASKS:
1. After successful logout, force a full page reload to refresh the CSRF meta token.
   - Client change: In the logout button handler, after a successful /api/logout response, call location.replace('/') or location.reload() instead of only changing the hash.
2. Optionally harden session rotation handling (defensive enhancement):
   - If you prefer not to reload the page, return a fresh CSRF token from /api/logout and update the <meta name="csrf-token"> content on the client before proceeding. This is optional if Task 1 is implemented.

DECISION:
FAIL