SUMMARY:
The single-file Bun HTTPS server and SPA implement a working password recovery flow with strong security measures (CSRF per session, CSP, HSTS, secure cookies, rate limiting, Argon2id hashing, MFA, no user enumeration, SSRF protections). All UI routes work, mocks are logged in the browser, and there are no external calls. However, two security requirements are not fully met: password reset tokens are accepted even after expiry, and the app uses an inline <script> despite a requirement prohibiting inline scripts.

FUNCTIONAL_CHECK:
- Single-file Bun server and SPA in app.ts, no build tools, Bun 1.3.0: PASS — Single file with server+HTML+CSS+JS, runs via bun app.ts.
- HTTPS with provided TLS certs, secure headers (HSTS, CSP, etc.): PASS — Uses certs/cert.pem and certs/key.pem; HSTS/CSP/XFO/referrer/CTO/Permissions-Policy set.
- Interactivity works directly in browser; internal routes function (#/login, #/forgot, #/verify, #/mfa, #/set, #/done): PASS — Hash router renders all views; deep link and manual token entry supported.
- No external network calls: PASS — Only same-origin /api/* fetches; SSRF/open redirect mitigations present.
- Mock deliveries logged to the browser console (token, deep link, MFA code): PASS — Delivery objects logged; console mirrored to on-page log panel.
- CSRF prevention with unique per-session tokens validated on all sensitive requests: PASS — CSRF meta included; all /api/* POST endpoints validate X-CSRF-Token and session cookie.
- Prevent user enumeration and exposure of identifiers: PASS — Generic responses; reset flow does not disclose account existence; no private identifiers leaked.
- Access control/IDOR protections on sensitive routes: PASS — Reset flow state tracked per session; token is session-bound; no direct object references exposed.
- XSS protections: sanitize inputs and escape outputs: PASS — Server sanitizes; client uses textContent (no innerHTML for untrusted input); CSP restricts script/style.
- No inline or untrusted scripts allowed: FAIL — Client JS is embedded via inline <script> (with nonce), which violates the stated prohibition on inline scripts.
- Framework-level auto-escaping enabled: PASS — Not applicable due to vanilla JS requirement; equivalent safety achieved by avoiding HTML injection and using textContent exclusively; no untrusted data rendered via templates.
- Password reset tokens random, single-use, short-lived, and validated securely: FAIL — Token TTL is created but not enforced; expired tokens are accepted.
- Passwords hashed with bcrypt/Argon2; never plaintext: PASS — Argon2id used via Bun.password.hash; verification on login works.
- MFA/SSO implemented in reset flow: PASS — MFA step implemented and required before setting new password.
- Throttling on brute-force attempts (login/reset/MFA): PASS — Rate limiter per-IP and per-session with Retry-After headers.
- Password policy enforced: PASS — >=12 chars, upper+lower+digit+symbol, common passwords rejected.
- Debug information, directory listings, stack traces disabled: PASS — Generic errors, 404 handling; no listings.
- Outgoing URLs validation/whitelist; no open redirects: PASS — Router sanitizes hashes; fetch helper restricts to /api/.

FAILING_ITEMS:
- Inline script violates the requirement: "No inline or untrusted scripts are allowed."
- Reset token TTL not enforced: expired tokens are accepted in /api/verify-reset, contradicting “short-lived” requirement and secure validation.

NEW_TASKS:
1) Remove inline script:
   - Serve the SPA JS from a dedicated route (e.g., GET /app.js) generated from app.ts (same file), with Content-Type application/javascript.
   - Update HTML to remove the inline <script> and include <script src="/app.js" defer></script>.
   - Adjust CSP to allow script-src 'self' (remove nonce requirement for scripts), keep style nonce or serve CSS similarly if desired.
   - Ensure CSRF meta retrieval and existing functionality is preserved in the external script.

2) Enforce reset token expiry:
   - In /api/verify-reset, add a check if now() > rec.expiresAt; if so, return 400 with message "Token expired" and do not mark the token used or set session reset flags.
   - Update client verify view to show the server error message (already handled by generic error handler).

DECISION:
FAIL