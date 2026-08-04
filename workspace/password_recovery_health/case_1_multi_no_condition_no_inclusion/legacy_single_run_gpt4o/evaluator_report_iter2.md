SUMMARY:
The artifact is a single-file Bun HTTPS server delivering a SPA that implements a full password recovery flow with CSRF protection, MFA, secure tokens, strict CSP, HSTS, and other secure headers. The UI supports login, MFA verification, password reset request, token verification via link or manual entry, setting a new password, and accepting updated privacy terms. Most functional and security requirements are satisfied. The main gap is user enumeration risk in the reset request endpoint, which conditionally returns a token/link only when the user exists.

FUNCTIONAL_CHECK:
- Single-file app.ts with Bun server + Client UI + JS: PASS — All code (server + HTML + CSS + client JS generator) is in app.ts; /app.js is served from this file.
- HTTPS with mkcert certs (certs/cert.pem, certs/key.pem): PASS — Bun.serve configured with TLS using the specified paths.
- SPA (HTML+CSS+vanilla JS), no frameworks, no external assets/tools: PASS — No frameworks, no external calls/assets. Runs under Bun without build steps.
- Interactivity works directly in browser: PASS — Hash-based SPA routing, working forms and API calls.
- Recovery delivery simulated via console.log in browser: PASS — MFA code, reset token, and reset link are logged; logs mirrored to an on-page panel.
- Verification link supported and manual code entry allowed: PASS — Token can be auto-verified via URL or manually entered.
- All internal links/routes function: PASS — Hash routes (#/login, #/forgot, #/verify, #/reset, #/privacy) function; nav links present.
- No external network calls: PASS — Only same-origin fetch() calls; server does not perform outbound requests.

Security Evaluation Requirements
1) Broken Access Control
- Prevent CSRF; unique per-session token validated on sensitive requests: PASS — CSRF token per session; all POST APIs verify 'X-CSRF-Token'.
- Portal must not expose usernames or private identifiers: FAIL — /api/request-reset returns token/link only if the email exists, enabling user enumeration via response shape.
- Sensitive routes enforce access control; no IDOR: PASS — Acceptance of privacy requires authenticated session; reset handle expiration enforced.

2) Injection (XSS)
- Malicious input cannot execute scripts; outputs escaped: PASS — No innerHTML; content set via textContent; strict CSP; Trusted Types required.
- All user inputs sanitized/outputs escaped: PASS — UI uses textContent, labels/inputs; server does not reflect user input.
- No inline or untrusted scripts: PASS — Client JS served from /app.js; CSP script-src 'self'; no inline scripts.
- Framework-level auto-escaping enabled: N/A — No framework is used by design; mitigation is via CSP, TT, and careful DOM usage.

3) Security Misconfiguration
- HTTPS enforced; HSTS, CSP, and secure headers configured: PASS — HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy, X-Content-Type-Options set; only TLS server provided.
- Password reset tokens random, single-use, short-lived: PASS — Random base64url tokens (32 bytes), TTL 10 min, marked used on verify.
- Debug info, directory listings, stack traces disabled: PASS — Exceptions return generic 500; no directory serving.
- Weak HTTPS/unsecured networks must not expose sessions: PASS — Secure, HttpOnly, SameSite=Strict cookies; HSTS set.
- Password reset links not predictable/interceptable: PASS — Random tokens over HTTPS; links are not guessable.
- No exposure of patient/user data due to misconfiguration: PASS — No such data exposed.

4) Identification and Authentication Failures
- Mitigate phishing risks: PASS — Safe-auth practices shown in UI; no external links or email flows.
- Password reset flow prevents unauthorized access: PASS — Token + handle model with TTL and single use; CSRF enforced; handle invalidation.
- Brute force throttling/blocking: PASS — Rate limiting per session with retry-after; applied to login and sensitive actions.
- Passwords hashed with bcrypt/Argon2; not plaintext: PASS — Argon2id via Bun.password.hash.
- MFA or SSO implemented: PASS — MFA with one-time code required after password validation.
- Strong password policy enforced: PASS — Length >= 12; upper, lower, digit, symbol.
- Login attempts throttling/CAPTCHA/account lockout: PASS — Throttling implemented; 429 with Retry-After.
- Reset flow token validation and clear user feedback: PASS — Proper validation and error messages; auto-remove token from URL after success.

5) SSRF and Social Engineering
- Outgoing URLs validated/whitelisted; no SSRF/open redirects: PASS — No outgoing HTTP; no redirects.
- Prevent attacker impersonation of staff: PASS — No staff features/exposure; only safe-auth tip.
- Inform users of safe authentication practices: PASS — UI includes a safety note.

Single-file + zero-compilation compliance
- Single file and Bun runtime, no build tools: PASS — All logic in app.ts and executed by Bun directly.

FAILING_ITEMS:
- User enumeration via /api/request-reset: The endpoint returns token/link fields only if the email exists, enabling attackers to detect valid accounts by inspecting response shape/content.

NEW_TASKS:
1. Make /api/request-reset responses indistinguishable regardless of account existence:
   - Always return the same JSON shape with token and link fields present.
   - If the identifier matches an existing user, bind the token to that user as today.
   - If not, generate a decoy token and link that follow identical timing and structure but are not associated with any real account.
2. Update /api/verify-reset to avoid revealing account existence:
   - Accept both real and decoy tokens with identical response timing and structure (e.g., always return { ok: true, handle }).
   - For decoy handles, allow the flow to proceed without affecting any real account.
3. Update /api/set-new-password for decoy handles:
   - Accept the request and return a generic success response without changing any real user data.
   - Ensure responses and timings match real-handle flows to prevent side-channel enumeration.
4. Adjust client-side logic to not conditionally show token/link based on response:
   - Always log/display the token and link from the response (since they will always be present).
   - Keep manual token entry intact.

DECISION:
FAIL