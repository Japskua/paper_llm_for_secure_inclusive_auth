SUMMARY:
The single-file Bun HTTPS SPA implements a secure password recovery flow with CSRF protection, CSP, HSTS, bcrypt hashing, MFA, strong password policy, and accessible UX for dyslexia. The UI and internal navigation work, tokens/codes are logged in the browser console, and no external calls are made. However, password reset tokens are not strictly single-use upon validation, MFA verification lacks throttling/expiry, and rate limiting is scoped per session (easy to evade by rotating sessions). These issues violate specific security acceptance criteria.

FUNCTIONAL_CHECK:
- Deliverable: Single file (app.ts) with Bun server + Client UI + inline JS: PASS — Everything is in app.ts; Bun 1.3.0 can serve TS directly; no bundlers; no external assets.
- Semantic HTML, minimal inline styles, comments mapping to requirements: PASS — Semantic tags used; minimal inline style; comments reference Security sections.
- Interactivity works directly in browser, internal navigation: PASS — Hash router for #login, #forgot, #reset, #new-password, #mfa, #success, #help all function.
- Mock delivery via browser console; reset token returned to UI and logged: PASS — API returns tokenHint and log messages; client logs to console and on-page Logs.

Security 1 — Broken Access Control:
- CSRF prevention: unique per session, validated on all sensitive requests: PASS — CSRF token created per session; validated on all /api/* POST requests.
- Portal not exposing usernames or private identifiers: PASS — Responses/logs avoid usernames; generic responses to avoid enumeration.
- Sensitive routes enforce access control; no IDOR: PASS — set-password derives target from session.user or validated reset token; no user parameter accepted.
- Sessions must not allow unintended actions: PASS — All state-changing endpoints require valid CSRF; no state changes via GET.

Security 2 — Injection (XSS):
- Malicious input cannot execute scripts: PASS — DOM APIs with textContent; no unsanitized HTML injection.
- Inputs sanitized and outputs escaped: PASS — UI uses textContent; sanitize helper; server avoids reflecting user input.
- No inline or untrusted scripts: PASS (within constraints) — Single inline script is protected with a CSP nonce and restricted by CSP; no third-party scripts.
- Framework-level auto-escaping enabled: N/A (No frameworks by requirement) — Achieved equivalent safety via manual DOM APIs and CSP.

Security 3 — Security Misconfiguration:
- HTTPS enforced; HSTS, CSP, secure headers configured: PASS — HTTPS via tls cert/key; HSTS, X-Frame-Options, Referrer-Policy, X-Content-Type-Options, Permissions-Policy; CSP with nonce.
- Password reset tokens random, single-use, short-lived: FAIL — Random and short-lived (10 min) are OK, but not single-use at validation; tokens remain reusable until password is set.
- Debug info, directory listings, stack traces disabled: PASS — Errors return generic 500; only server console logs contain stack; no directory listing.
- Weak HTTPS or unsecured networks must not expose sessions: PASS — Secure, HttpOnly, SameSite=Strict cookie; HTTPS-only server.
- Password reset links not predictable or interceptable: PASS — High-entropy tokens; links only shown in console/logs for demo.

Security 4 — Identification and Authentication Failures:
- Phishing mitigation: PASS — Help/Safety guidance; HTTPS; MFA.
- Password reset flow prevents unauthorized access: PASS — Requires valid token or authenticated session; generic responses.
- Automated guessing attempts throttled/blocked: FAIL — Login is throttled, but MFA verification lacks throttling/expiry; rate limiting is per-session (can be bypassed by rotating sessions).
- Passwords hashed with bcrypt/Argon2, never plaintext: PASS — bcrypt via Bun.password.hash.
- MFA or SSO implemented: PASS — MFA implemented with one-time code.
- Strong password policy enforced: PASS — Server-side checks length ≥12, upper/lower/digit/special.
- Login throttling/CAPTCHA/lockout: PASS — Throttling implemented (but see rate limiter scope issue below).
- Reset flow validates tokens securely, clear feedback: PASS — Validation endpoint and clear messages.

Security 5 — SSRF and Social Engineering:
- Outgoing URLs validated or whitelisted; no open redirects: PASS — No outgoing requests; guards against absolute next parameter.
- Prevent staff impersonation/social engineering: PASS — Help guidance; no staff channels in flow.
- Users informed of safe practices: PASS — Help & Safety section includes key advice.

Single-file + Zero-compilation Compliance:
- Single-file app.ts and Bun runtime only: PASS — All code/resources embedded; no build step; no external assets.

FAILING_ITEMS:
- Reset tokens are not single-use at validation: A valid reset token can be reused across sessions before the password is actually changed (token marked used only after /api/set-password).
- MFA verification lacks throttling and expiry: /api/verify-mfa does not rate-limit attempts or expire codes; enables brute forcing 6-digit MFA if an attacker has valid password and a pending MFA session.
- Rate limiting is per-session (stored in session.rate): An attacker can bypass throttling by rotating sessions (e.g., no cookie or clearing cookie), undermining brute-force protections on /api/login and /api/request-reset.

NEW_TASKS:
1) Enforce single-use reset tokens upon validation:
   - In /api/validate-reset, after finding a valid token, immediately set matched.used = true, and bind the reset to the session via session.resetUser = username and session.resetToken = token.
   - Ensure /api/set-password checks only session.resetUser/session.resetToken (already present). No further changes needed to invalidate tokens there.
2) Add MFA code expiry and attempt throttling:
   - Extend Session type with mfaExpiresAt: number and mfaAttempts: number.
   - In /api/login, when generating MFA code, set session.mfaExpiresAt = now + 5*60*1000 and session.mfaAttempts = 5.
   - In /api/verify-mfa, before comparing codes: 
     - If now > mfaExpiresAt, clear MFA state and return 401 "MFA expired; please sign in again."
     - Decrement mfaAttempts on each failed attempt; if <=0, clear MFA state and return 429 "Too many MFA attempts; sign in again."
   - Optionally log a user-safe message via the client Logs panel.
3) Implement global, IP-scoped rate limiting:
   - Add a top-level Map<string, number[]> (e.g., rateBuckets) keyed by `${key}:${ip}`.
   - Implement checkRateGlobal(ip, key, limit = 5, windowMs = 5*60*1000) that prunes/updates this global bucket.
   - Replace existing checkRate(session, ...) calls in /api/login and /api/request-reset with checkRateGlobal(ip, ...).
   - Add rate limiting to /api/verify-mfa using checkRateGlobal(ip, 'verify-mfa', suitable limits like 5 per 5 minutes).
4) Optional hardening for MFA:
   - On successful /api/login (MFA issuance), also store a short-lived nonce in session and require it on /api/verify-mfa to tie attempts to that issuance.
   - Clear MFA state (pendingMFA, mfaCode, mfaExpiresAt, mfaAttempts) after success or terminal failure/expiry.

DECISION:
FAIL