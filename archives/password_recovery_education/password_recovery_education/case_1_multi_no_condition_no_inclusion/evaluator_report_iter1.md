SUMMARY:
The single-file Bun app generally meets the functional and UX requirements for a password recovery flow, uses HTTPS with proper security headers, enforces CSRF, implements MFA, and logs mock delivery in the browser console. However, it violates the security requirement “No inline or untrusted scripts are allowed” by embedding a large inline script (even though nonce-protected), and it does not enable a framework-level auto-escaping mechanism as explicitly required.

FUNCTIONAL_CHECK:
- SPA + single-file + Bun HTTPS server with certs at certs/cert.pem and certs/key.pem: PASS — Single app.ts with Bun.serve for HTTPS and HTTP-to-HTTPS redirect.
- All internal links function (login, forgot password, enter code, reset password, MFA, confirmation): PASS — Hash-based routing works and routes are implemented.
- Interactivity works directly in the browser from server’s HTML+CSS+JS: PASS — No build tools required; client JS runs directly.
- No external network calls or assets: PASS — Only same-origin API calls; no external assets.
- Mock delivery via console.log in the browser (reset token and MFA code): PASS — Tokens/codes are logged to the Logs panel and console.
- Allow manual submission of verification code: PASS — “Enter Verification Code” view implemented.
- CSRF: Unique per session, validated on all sensitive POST requests: PASS — Session-level CSRF token and header validation applied to all POST /api/* endpoints.
- Prevent user enumeration/exposure of identifiers: PASS — Generic responses; no disclosure of existence; messages are neutral.
- Sensitive routes enforce access control; no IDOR: PASS — Reset uses random, single-use, short-lived tokens; password set requires verified, unexpired token.
- XSS protections (sanitize input, escape output): PASS — Inputs normalized/sanitized; DOM APIs used (no innerHTML); template values escaped server-side; CSP enabled.
- No inline or untrusted scripts are allowed: FAIL — A large inline script is embedded in the HTML (nonce-protected but still inline).
- Framework-level auto-escaping enabled (e.g., React/Angular/Django): FAIL — No framework templating; DOM API and manual escaping used instead.
- HTTPS enforced; HSTS, CSP, secure headers configured: PASS — HSTS, CSP with nonce, X-Frame-Options, Referrer-Policy, Permissions-Policy, X-Content-Type-Options.
- Password reset tokens random, single-use, short-lived: PASS — Random base64url tokens, 10 min TTL, verified/used flags.
- Debug info/stack traces disabled: PASS — Generic error messages; no stack traces returned.
- Weak HTTPS/unsecured networks should not expose sessions: PASS — Secure, HttpOnly, SameSite=Strict session cookie; HTTPS enforced.
- Password reset links not predictable/interceptable: PASS — Strong random tokens; no predictable info.
- Authentication: mitigate phishing: PASS — On-page safety banner; HTTPS enforced with HSTS and CSP.
- Prevent unauthorized reset: PASS — Token verification + one-time use required.
- Brute force throttling: PASS — Rate limiting on login, reset request, and token verification.
- Passwords hashed bcrypt/Argon2: PASS — Argon2id via Bun.password.hash.
- MFA or SSO implemented: PASS — MFA with time-limited code implemented (simulated delivery).
- Strong password policy enforced: PASS — Client- and server-side checks for length, classes, no whitespace.
- Reset flow token validation and clear user feedback: PASS — Clear error/success messages; proper transitions.
- SSRF/open redirects: PASS — No outgoing URL fetches; no open redirects; only fixed HTTP→HTTPS redirect.
- Social engineering: PASS — Safety guidance provided to users.

FAILING_ITEMS:
- Inline script violates the requirement “No inline or untrusted scripts are allowed,” even though protected by a CSP nonce.
- No framework-level auto-escaping is enabled as explicitly required (example given: React, Angular, Django), which conflicts with the “no frameworks” constraint. Current implementation relies on DOM APIs and manual escaping but does not satisfy the letter of this requirement.

NEW_TASKS:
1) Move client JavaScript out of the HTML into a same-origin endpoint served from app.ts (e.g., GET /app.js), and include it via a <script src="/app.js"> tag.
2) Update the Content-Security-Policy to disallow inline scripts: remove the nonce use and set script-src 'self'; keep other directives intact.
3) Ensure no inline event handlers or additional inline scripts exist in the HTML (audit and remove any).
4) Implement a minimal auto-escaping rendering helper (template function) that defaults to textContent for dynamic content and prohibits unsafe HTML, then refactor UI rendering to use it consistently. Document and justify this as the app’s “auto-escaping layer” to meet the spirit of the “framework-level auto-escaping” requirement without adding external frameworks.

DECISION:
FAIL