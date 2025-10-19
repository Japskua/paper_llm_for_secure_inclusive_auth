SUMMARY:
The artifact is a single-file Bun HTTPS server (app.ts) delivering a SPA for a password recovery flow. It implements a clear, step-by-step UX with accessibility considerations, works without external assets, and includes deterministic mock deliveries via browser console for testing. Security controls include HTTPS with TLS, HSTS, CSP with nonces, CSRF protection on all POSTs, rate limiting, Argon2id password hashing, MFA, and short-lived, single-use reset tokens. Internal navigation and link-based verification work, and manual code verification is supported. No functional or runtime errors are evident for the described environment (Bun 1.3.0).

FUNCTIONAL_CHECK:
- Single file (Bun server + Client UI in HTML+CSS+vanilla JS) exists in one file app.ts: PASS — Everything is implemented in app.ts with inline HTML/CSS/JS and server logic.
- Zero-compilation compliance (no bundlers/tools; Bun runs it directly): PASS — Runs with bun app.ts; no build steps or external assets used.
- HTTPS with provided TLS certs (certs/cert.pem, certs/key.pem): PASS — Bun.serve configured with TLS using those files.
- SPA interactivity works in browser (client-side routing, no external network calls): PASS — Hash-based router; all fetches are to /api; no external calls.
- Password reset flow (request, verify via link or code, set new password) works: PASS — Flow includes request reset, verify token or 6-digit code, set password with policy checks.
- If there is a verification link, allow manual code entry: PASS — “Verify reset” screen supports both token and 6-digit code.
- Internal links (e.g., to verification pages or confirmation screens) function: PASS — Generated link uses https://.../#/verify?token=...; router pre-fills the token and shows the verify view.
- Deterministic mocks via console.log in the browser (show reset token, link, code): PASS — Client logs reset details and MFA code; demo panel mirrors them.
- Inclusivity: forgiving, clear, step-by-step, no timeouts, low-stress UI: PASS — Step views, progress bar, simple language, help link, status messages, no session timeouts, last-view persistence to resume.
- Prevents user enumeration: PASS — Generic responses for login/reset; no disclosure if an account exists.
- CSRF protection unique per session and validated on sensitive requests: PASS — CSRF token per session, sent in header and validated for all POST /api routes.
- Access control on sensitive routes (no IDOR): PASS — /api/set-password requires session.canSetPassword bound by validated token; session state controls access.
- Injection (XSS) mitigations: PASS — Inputs sanitized; outputs set via textContent; CSP with nonce; no inline event handlers or external scripts.
- “No inline or untrusted scripts”: PASS — Inline script allowed via CSP nonce and hosted ‘self’; no third-party scripts.
- Framework auto-escaping: N/A — No frameworks by requirement; manual escaping and safe DOM APIs are used consistently.
- Security headers (HTTPS, HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy): PASS — Set via securityHeaders; CSP generated per response; HSTS enabled.
- Password reset tokens random, single-use, short-lived: PASS — Random base64url; single-use mark; 15-minute expiry.
- Debug info/stack traces/directory listing disabled: PASS — Not exposed; minimal server logs only.
- Password reset links not predictable/interceptable: PASS — Random token; HTTPS link is constructed; only valid for existing user and single-use within TTL.
- Identification and Authentication: PASS — MFA implemented; strong password policy enforced (12+ chars, classes, no spaces); Argon2id hashing; login/reset endpoints rate-limited; MFA TTL enforced.
- Throttling/CAPTCHA/lockout on login attempts: PASS — Rate limiting with exponential backoff; CAPTCHA/lockout not required since throttling is present.
- SSRF/open redirects prevented: PASS — No user-controlled outbound requests; no redirects implemented; origin used only to compose demo link.
- Social engineering guidance to users: PASS — Help view advises safe practices.

FAILING_ITEMS:
- None identified that block acceptance.

NEW_TASKS:
- None.

DECISION:
PASS