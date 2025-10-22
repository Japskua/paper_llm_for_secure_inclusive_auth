SUMMARY:
The provided app.ts implements a complete HTTPS Bun server and a single-page password recovery UI with strong security controls. It meets the core functional, UX, and security requirements: CSRF protection, XSS-hardening via CSP and safe DOM APIs, secure headers, Argon2id password hashing, rate limiting, single-use reset tokens with TTL, MFA in the reset flow, and no external network calls. All UI flows and internal links function, tokens and codes are surfaced via browser console logs, and everything is contained in a single file.

FUNCTIONAL_CHECK:
- Single-file + zero-compilation: PASS — Entire server, HTML, CSS, and client JS exist in app.ts. No build tools; Bun serves TS directly.
- HTTPS + TLS certs: PASS — Bun.serve configured with certs/cert.pem and certs/key.pem; HSTS enabled.
- SPA interactivity: PASS — Hash router renders routes (#/login, #/forgot, #/verify, #/mfa, #/set, #/done). Interactivity works via /app.js served from the same file.
- Internal links function: PASS — Navigation links and deep link (#/verify?token=...) work; verify view can auto-submit token or accept manual input.
- No external network calls: PASS — No external fetch; client fetch helper gates to /api/ prefix only.
- Mock delivery via console.log (browser) and deterministic values: PASS — Reset token and deep link returned to UI and logged; MFA code deterministic ("246810") and logged.
- CSRF prevention: PASS — Unique CSRF token per session; validated on all POST /api/* routes; cookie SameSite=Strict and HttpOnly.
- No user enumeration / private identifiers: PASS — Generic responses for login and reset request; no exposure of existence; no usernames in responses.
- Access control / no IDOR: PASS — Reset tokens bound to session; set-password requires resetVerified + mfaVerified; no direct object references exposed.
- XSS protection: PASS — CSP with script-src 'self' (no inline scripts); DOM updates via textContent; input sanitized on client and server; no innerHTML for untrusted content.
- “No inline or untrusted scripts”: PASS — No inline scripts; only /app.js from same origin; CSP enforces this.
- Secure headers and configuration: PASS — CSP, HSTS, X-Frame-Options DENY, Referrer-Policy no-referrer, X-Content-Type-Options nosniff, Permissions-Policy; no directory listing or debug traces.
- Reset token security: PASS — cryptographically random, single-use, session-bound, 15-minute TTL; rejected if expired/used.
- Password storage: PASS — Argon2id hashing via Bun.password; no plaintext storage.
- Brute-force protections: PASS — Rate limiting on login and sensitive endpoints; Retry-After provided.
- MFA/SSO: PASS — MFA required in reset flow (send + verify).
- Strong password policy: PASS — Enforces minimum length and character classes; rejects common passwords.
- Phishing/awareness: PASS — UI includes safety notes; HTTPS used; no email delivery beyond simulated logs.
- SSRF/Open redirects: PASS — No outgoing URLs; client blocks non-/api/ fetch; hash router rejects suspicious hashes.
- Semantic HTML + minimal inline styles + comments mapping: PASS — Semantic elements (header, main, section, aside, footer); minimal inline CSS with CSP nonce; comments map to BAC, XSS, etc.

FAILING_ITEMS:
- None found that violate the stated requirements or acceptance criteria within this context. Note: “Framework-level auto-escaping must be enabled” is not applicable given the explicit requirement to use plain HTML+JS with no frameworks; equivalent protections are implemented via CSP and safe DOM APIs.

NEW_TASKS:
- None.

DECISION:
PASS