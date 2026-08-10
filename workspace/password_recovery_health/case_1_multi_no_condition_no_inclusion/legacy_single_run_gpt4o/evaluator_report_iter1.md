SUMMARY:
The single-file Bun HTTPS SPA implements the password recovery flow with strong security controls: CSRF tokens per session, secure cookies, MFA, Argon2id hashing, rate limiting, random single-use reset tokens/handles, strict headers (HSTS, CSP, XFO), and no external calls. UI/UX is functional with manual token entry and link verification, and delivery logs are mirrored to the browser console/UI. However, it violates the “No inline scripts” requirement and does not meet the “framework-level auto-escaping” requirement. There is also a minor CSP misconfiguration risk due to an empty meta CSP tag.

FUNCTIONAL_CHECK:
- Deliverable: Single file app.ts with Bun server + Client UI (HTML+CSS+vanilla JS)
  PASS — All code is in app.ts; Bun serves HTML and handles API.
- Zero-compilation and no build tools
  PASS — Runs via bun app.ts with no external build steps.
- HTTPS with mkcert certs at certs/cert.pem and certs/key.pem
  PASS — TLS cert/key are read from certs/, server serves HTTPS on 8443.
- SPA interactivity directly in browser (no external assets or network calls)
  PASS — All logic inline/same-origin; no external requests.
- Reset delivery/verification via console.log (deterministic mock values) and visible in UI
  PASS — Tokens/links and MFA codes are console.logged and shown in the Logs panel.
- Verification link present and manual token submission also allowed
  PASS — Manual token form and auto-verification from URL query; query param removed after verify.
- All internal links function (routing)
  PASS — Hash-based router for /login, /forgot, /verify, /reset, /privacy.

Security Evaluation Requirements:
1) Broken Access Control
  - CSRF protection, unique per-session token validated on sensitive requests
    PASS — Per-session CSRF token; all POST handlers verify X-CSRF-Token.
  - Prevent exposure of usernames/identifiers
    PASS — Generic error messages; no enumeration; no private IDs in responses.
  - Sensitive routes enforce access control; no IDOR
    PASS — accept-privacy gated by authenticated session; reset handle ties to user; no user-controlled IDs.
  - Sessions must not allow unintended actions due to CSRF
    PASS — All state-changing routes are POST and CSRF-validated; cookies SameSite=Strict.

2) Injection (XSS)
  - Malicious input cannot execute scripts; outputs escaped
    PASS — DOM updates via textContent; no innerHTML; args sanitized before rendering in logs.
  - All user inputs sanitized and outputs escaped
    PASS — No HTML injection; controlled API usage; server responds JSON only.
  - No inline or untrusted scripts are allowed
    FAIL — Client code is in an inline <script> tag (nonce-protected but still inline).
  - Framework-level auto-escaping enabled (e.g., React/Angular/Django)
    FAIL — Vanilla JS used; no framework-level auto-escaping in place.

3) Security Misconfiguration
  - HTTPS enforced; HSTS, CSP, and secure headers configured
    PASS — HSTS, CSP with nonces, XFO, Referrer-Policy, Permissions-Policy, nosniff set. Note: redundant empty meta CSP tag present (see failing items).
  - Password reset tokens random, single-use, short-lived
    PASS — crypto-strong tokens with TTL and single-use; separate short-lived reset handle.
  - Debug info, directory listings, stack traces disabled in production
    PASS — Catches errors and returns generic 500; no stack traces to client.
  - Weak HTTPS/unsecured networks must not expose sessions
    PASS — HTTPS only; Secure+HttpOnly+SameSite=Strict cookies.
  - Reset links not predictable or interceptable
    PASS — Random token; link only revealed in console/Logs for testing.
  - No data exposure due to misconfiguration
    PASS — No PII leakage; minimal demo user in-memory.

4) Identification and Authentication Failures
  - Mitigate phishing risks
    PASS — Safe-auth practices note displayed; strict CSP and HTTPS.
  - Password reset flow prevents unauthorized access
    PASS — Token and handle validation; single-use; TTL; CSRF on all steps.
  - Brute force throttling/blocking
    PASS — Per-session rate limiting across login/MFA/reset endpoints. (Improvement: global/IP-level rate-limits could enhance.)
  - Passwords hashed with bcrypt/Argon2; never plaintext
    PASS — Argon2id via Bun.password.hash.
  - MFA or SSO implemented
    PASS — MFA code flow implemented.
  - Strong password policy enforced
    PASS — 12+ chars, upper, lower, digit, symbol.
  - Login attempts throttled/CAPTCHA/lockout
    PASS — Throttling present (per-session).
  - Reset flow validates tokens securely; clear feedback
    PASS — Proper validation and user feedback.

5) SSRF and Social Engineering
  - Outgoing URLs validated/whitelisted; prevent SSRF/open redirects
    PASS — No outgoing network calls; no redirects.
  - Prevent staff impersonation/social engineering
    PASS — No such surface; safe-auth tips shown.
  - Inform users of safe authentication practices
    PASS — Sidebar hints provided.

Single-file + zero-compilation compliance:
  PASS — Single app.ts file; Bun 1.3.0 compatible; no bundlers/assets.

FAILING_ITEMS:
- Inline script present despite requirement “No inline or untrusted scripts are allowed.”
- “Framework-level auto-escaping must be enabled” not satisfied (no framework; vanilla JS used).
- Minor CSP misconfiguration risk: an empty meta http-equiv="Content-Security-Policy" tag is present and may conflict with header policy on some browsers.

NEW_TASKS:
1) Remove inline script:
   - Serve client JS from a same-origin route (e.g., GET /app.js) generated by app.ts (no separate file on disk).
   - Replace the inline <script> tag with <script src="/app.js"></script>.
   - Update CSP to remove nonce and set script-src to 'self' only (and optionally add 'strict-dynamic' if needed).
2) Remove the empty meta CSP tag:
   - Delete <meta http-equiv="Content-Security-Policy" content=""> from the HTML to avoid any conflicting policies.
3) Strengthen auto-escaping posture to address “framework-level auto-escaping” requirement within constraints:
   - Add CSP Trusted Types directives: include "require-trusted-types-for 'script'; trusted-types default;" in Content-Security-Policy.
   - Ensure client code does not use eval/dynamic script creation; continue using only textContent/attribute setters.
   - Document and enforce the existing safe DOM helpers (el(), info(), formField()) as the only way to render user-supplied data, keeping innerHTML unused.

DECISION:
FAIL