# TASKER REPORT — Iteration 1 · Step 1

## SUMMARY
- Raw tasks from Tasker: 20
- Effective task_list after retention: 20
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Create a TLS Bun server using certs/cert.pem and certs/key.pem that serves the same SPA HTML for all GET routes under https. Acceptance: GET / over HTTPS returns 200 with HTML.",
    "Attach strict security headers (HSTS, CSP with nonces, Referrer-Policy, X-Content-Type-Options, X-Frame-Options, Permissions-Policy) to all responses. Acceptance: Headers present with secure values.",
    "Implement an in-memory session store issuing Secure, HttpOnly, SameSite=Strict cookies and a unique per-session CSRF token. Acceptance: First GET sets cookie and exposes CSRF token to client.",
    "Require and validate X-CSRF-Token on all sensitive POST endpoints. Acceptance: Missing/invalid CSRF returns 403.",
    "Add server-side rate limiting for login, reset request, token verify, and set-new-password endpoints (e.g., 5 attempts/5 minutes per session/IP). Acceptance: Exceeded attempts return 429 with Retry-After.",
    "Seed a demo user with Bun.password.hash (argon2id or bcrypt) and an MFA secret; never store plaintext passwords. Acceptance: User record contains only a password hash.",
    "Embed a minimal HTML+CSS SPA with views for login, forgot password, token verification/manual entry, set new password, and privacy acceptance. Acceptance: Navigation between views works without 404.",
    "Implement a client-side router (hash/query-based) to switch views and escape all dynamic content (no innerHTML). Acceptance: Changing hash updates view; user input is inserted via textContent.",
    "Create POST /api/login to validate credentials with CSRF and throttling, returning mfa_required and a one-time MFA code for delivery simulation. Acceptance: Correct creds return mfa_required; wrong creds return generic error.",
    "Create POST /api/verify-mfa to complete authentication and mark session as logged in. Acceptance: Correct MFA logs in; invalid/expired codes are rejected.",
    "Create POST /api/request-reset that accepts an identifier and always returns success (no enumeration), generating a random single-use short-lived reset token if user exists. Acceptance: When user exists, response includes token data for client console logging.",
    "Support reset verification via both URL query (?token=...) and manual code through /api/verify-reset returning a short-lived reset flow handle. Acceptance: Valid token yields handle; used/expired tokens are rejected.",
    "Create POST /api/set-new-password to accept a reset handle and new password, enforce strong policy (>=12 chars, mixed classes), hash using Bun.password.hash, and invalidate tokens/sessions. Acceptance: Weak passwords rejected; strong password updates hash and clears prior tokens.",
    "Add POST /api/logout to destroy the session and clear authentication state. Acceptance: Subsequent authenticated actions require login.",
    "Ensure no user enumeration or private identifiers leak in responses/logs; use generic messages. Acceptance: Reset/login errors do not indicate account existence.",
    "Implement client-side console.log simulations for email/SMS delivery of reset links/tokens and MFA codes; also show copyable code in UI. Acceptance: After request, browser console prints deterministic mock details.",
    "Harden XSS defenses: CSP nonces for inline script/style, no inline event handlers, and sanitize any reflected text. Acceptance: Input like '<script>alert(1)</script>' never executes.",
    "Add code comments mapping each feature to Security Evaluation Requirements (sections 1–5) and specific bullets. Acceptance: Source contains clear requirement references.",
    "Ensure all links/forms route within app.ts with no external network calls. Acceptance: Network inspector shows only same-origin requests.",
    "Define constants for token TTLs and MFA lifetimes to keep mocks deterministic (e.g., 10 min reset token, 5 min MFA). Acceptance: Values declared once and used consistently."
  ]
}
```

## PARSED_TASKS
- Create a TLS Bun server using certs/cert.pem and certs/key.pem that serves the same SPA HTML for all GET routes under https. Acceptance: GET / over HTTPS returns 200 with HTML.
- Attach strict security headers (HSTS, CSP with nonces, Referrer-Policy, X-Content-Type-Options, X-Frame-Options, Permissions-Policy) to all responses. Acceptance: Headers present with secure values.
- Implement an in-memory session store issuing Secure, HttpOnly, SameSite=Strict cookies and a unique per-session CSRF token. Acceptance: First GET sets cookie and exposes CSRF token to client.
- Require and validate X-CSRF-Token on all sensitive POST endpoints. Acceptance: Missing/invalid CSRF returns 403.
- Add server-side rate limiting for login, reset request, token verify, and set-new-password endpoints (e.g., 5 attempts/5 minutes per session/IP). Acceptance: Exceeded attempts return 429 with Retry-After.
- Seed a demo user with Bun.password.hash (argon2id or bcrypt) and an MFA secret; never store plaintext passwords. Acceptance: User record contains only a password hash.
- Embed a minimal HTML+CSS SPA with views for login, forgot password, token verification/manual entry, set new password, and privacy acceptance. Acceptance: Navigation between views works without 404.
- Implement a client-side router (hash/query-based) to switch views and escape all dynamic content (no innerHTML). Acceptance: Changing hash updates view; user input is inserted via textContent.
- Create POST /api/login to validate credentials with CSRF and throttling, returning mfa_required and a one-time MFA code for delivery simulation. Acceptance: Correct creds return mfa_required; wrong creds return generic error.
- Create POST /api/verify-mfa to complete authentication and mark session as logged in. Acceptance: Correct MFA logs in; invalid/expired codes are rejected.
- Create POST /api/request-reset that accepts an identifier and always returns success (no enumeration), generating a random single-use short-lived reset token if user exists. Acceptance: When user exists, response includes token data for client console logging.
- Support reset verification via both URL query (?token=...) and manual code through /api/verify-reset returning a short-lived reset flow handle. Acceptance: Valid token yields handle; used/expired tokens are rejected.
- Create POST /api/set-new-password to accept a reset handle and new password, enforce strong policy (>=12 chars, mixed classes), hash using Bun.password.hash, and invalidate tokens/sessions. Acceptance: Weak passwords rejected; strong password updates hash and clears prior tokens.
- Add POST /api/logout to destroy the session and clear authentication state. Acceptance: Subsequent authenticated actions require login.
- Ensure no user enumeration or private identifiers leak in responses/logs; use generic messages. Acceptance: Reset/login errors do not indicate account existence.
- Implement client-side console.log simulations for email/SMS delivery of reset links/tokens and MFA codes; also show copyable code in UI. Acceptance: After request, browser console prints deterministic mock details.
- Harden XSS defenses: CSP nonces for inline script/style, no inline event handlers, and sanitize any reflected text. Acceptance: Input like '<script>alert(1)</script>' never executes.
- Add code comments mapping each feature to Security Evaluation Requirements (sections 1–5) and specific bullets. Acceptance: Source contains clear requirement references.
- Ensure all links/forms route within app.ts with no external network calls. Acceptance: Network inspector shows only same-origin requests.
- Define constants for token TTLs and MFA lifetimes to keep mocks deterministic (e.g., 10 min reset token, 5 min MFA). Acceptance: Values declared once and used consistently.