SUMMARY:
The submitted app.ts implements a single-file Bun HTTPS server that serves a SPA for secure password recovery with MFA, CSRF protection, strong CSP, secure cookies, rate limiting, bcrypt hashing, and accessible UI. It meets the functional flow: login with MFA, expired-password change, request-reset via token link and manual token entry, and success confirmation. Security hardening is applied across the stack, and all mocks are logged in the browser console and an on-page log panel. No external calls are used, and TLS certs are loaded from the specified paths.

FUNCTIONAL_CHECK:
- Broken Access Control: CSRF prevention (unique per session, validated on all POST) — PASS. CSRF token issued per session, sent via header, validated for all /api/* POSTs.
- Broken Access Control: Do not expose usernames/identifiers — PASS. Generic messages for login and reset request; logs do not include usernames.
- Broken Access Control: No IDOR on sensitive routes — PASS. set-password gated by session-bound resetUser/resetToken; ignore client-supplied identifiers.
- Injection (XSS): Malicious input cannot execute scripts — PASS. DOM APIs with textContent, no dangerous innerHTML; CSP restrictive; no inline event-attributes.
- Injection (XSS): Inputs sanitized and outputs escaped — PASS. UI uses textContent and DOM creation, sanitize helper, no reflective HTML.
- Injection (XSS): No inline or untrusted scripts — PASS. Single inline script is authorized via CSP nonce (no 'unsafe-inline'); no external/untrusted scripts or inline event handlers.
- Injection (XSS): Framework auto-escaping — PASS (N/A). Requirement refers to frameworks; app uses vanilla DOM with explicit escaping.
- Security Misconfiguration: HTTPS enforced with TLS + HSTS, CSP, secure headers — PASS. Bun.serve with TLS certs, HSTS, X-Frame-Options, Referrer-Policy, X-Content-Type-Options, Permissions-Policy, CSP via headers and meta.
- Security Misconfiguration: Reset tokens random, single-use, short-lived — PASS. crypto-strong base64url tokens, 10-minute expiry, single-use; all tokens invalidated after password change.
- Security Misconfiguration: No debug info/stack traces — PASS. Server returns generic "Internal Error"; stack not exposed.
- Security Misconfiguration: Reset links not predictable — PASS. Cryptographically random tokens; no sequential/predictable values.
- Identification/Authentication: Phishing mitigation — PASS. Help section advises safe practices; HTTPS only; no revealing data.
- Identification/Authentication: Prevent unauthorized reset — PASS. Token validation and session binding required to set password.
- Identification/Authentication: Brute force mitigation — PASS. Global per-IP rate limits for login, request-reset, verify-mfa; per-session MFA attempt cap.
- Identification/Authentication: Passwords hashed with bcrypt — PASS. Bun.password.hash bcrypt cost 10.
- Identification/Authentication: MFA or SSO — PASS. Time-bound, per-session 6-digit MFA with nonce and attempt limits.
- Identification/Authentication: Strong password policy — PASS. Enforced length >= 12, upper/lower/digit/special.
- Identification/Authentication: Throttling/CAPTCHA/lockout — PASS. Throttling via per-IP rate limit + MFA attempt lockout.
- Identification/Authentication: Reset tokens validated, clear feedback — PASS. Friendly messages, invalid/expired errors, success logs.
- SSRF/Open Redirect: Outgoing URLs validated/whitelisted — PASS. No outgoing requests; reject absolute http(s) next params.
- SSRF/Social Engineering: Prevent impersonation — PASS. No staff contact flows; help text warns; no data leaks.
- Deliverable: Single file app.ts (server + client) — PASS. Entire app in one file.
- Deliverable: Semantic HTML, minimal inline styles, comments mapping to requirements — PASS. Semantic elements, minimal inline style usage, explicit [Security X] comments.
- Deliverable: All mocks via console.log in the browser; reset token logged — PASS. Tokens and MFA codes logged to console and mirrored in on-page Logs.
- Deliverable: If verification link exists, support manual code entry — PASS. #reset view accepts token; hash link #reset?token=… auto-validates.
- Deliverable: All internal links/flows work — PASS. Hash router supports login/forgot/reset/new-password/mfa/success/help.
- Deliverable: No external network calls; works in browser from Bun server — PASS. Local SPA and /api routes only.
- TLS cert paths certs/cert.pem and certs/key.pem used — PASS. Configured in Bun.serve TLS.

FAILING_ITEMS:
- None identified that block acceptance.

NEW_TASKS:
- None.

DECISION:
PASS