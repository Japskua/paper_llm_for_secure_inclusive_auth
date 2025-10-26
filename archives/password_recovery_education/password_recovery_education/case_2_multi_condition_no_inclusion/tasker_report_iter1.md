# TASKER REPORT — Iteration 1 · Step 1

## SUMMARY
- Raw tasks from Tasker: 20
- Effective task_list after retention: 20
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Create app.ts HTTPS server using certs/cert.pem and certs/key.pem that serves a single HTML page on GET / with CSP nonce and secure headers.",
    "Issue a secure HttpOnly SameSite=Strict session cookie and create an in-memory session store with a unique CSRF token per session.",
    "Validate CSRF on all POST /api/* routes, returning 403 for missing/invalid tokens and accepting only matching tokens.",
    "Initialize an in-memory user store with bcrypt-hashed passwords via Bun.password.hash and include user 'alex' with expired=true.",
    "Implement per-session/IP rate limiting for POST /api/login and POST /api/request-reset (e.g., 5 attempts per 5 minutes) returning 429 on exceed.",
    "Build SPA views (login, forgot, enter reset code, new password, MFA, success, help) and hash-based navigation without full page reloads.",
    "Create POST /api/login to verify credentials with bcrypt, respond with generic error on failure, and set a pendingMFA flag on success.",
    "Generate a per-session MFA code, log it to the browser console for mock delivery, and implement POST /api/verify-mfa that accepts the code (must always work for demo).",
    "Implement POST /api/request-reset that accepts email/username, always returns a generic response, and creates a single-use 10-minute reset token for existing users while logging the token to the browser console.",
    "Support reset via link and manual code by parsing #reset?token=... on the client and adding POST /api/validate-reset to verify and bind valid tokens to the session.",
    "Create password strength checks (>=12 chars with upper, lower, digit, special) and POST /api/set-password to bcrypt-hash and save, invalidating all reset tokens for that user.",
    "Ensure sensitive endpoints derive the target user from the authenticated session or validated reset token and reject any user-supplied identifiers (prevent IDOR).",
    "Sanitize and escape all user-controlled text (use textContent on the client and avoid reflecting unsanitized inputs on the server) to prevent XSS.",
    "Set strict security headers on all responses: HSTS, CSP with nonce (script-src 'self' 'nonce-...'), X-Frame-Options DENY, Referrer-Policy no-referrer, X-Content-Type-Options nosniff, and minimal Permissions-Policy.",
    "Reject or ignore any external or absolute redirect/next parameters and only permit internal hash navigation to prevent SSRF/open redirects.",
    "Add a Help view that explains phishing/MFA safety, not sharing passwords via email, and that tokens/codes are mocked via console.log for demo.",
    "Provide a dyslexia-friendly UI toggle (larger font, high contrast, readable spacing) stored per session and applied to the SPA.",
    "Log mock deliveries (MFA code and reset token) to the browser console upon generation, without revealing usernames in UI responses.",
    "Add requirement-mapped code comments throughout app.ts referencing each security requirement section and how it is fulfilled.",
    "Verify the app performs no external network calls and that all internal links/forms resolve via routes or hash handling within app.ts."
  ]
}
```

## PARSED_TASKS
- Create app.ts HTTPS server using certs/cert.pem and certs/key.pem that serves a single HTML page on GET / with CSP nonce and secure headers.
- Issue a secure HttpOnly SameSite=Strict session cookie and create an in-memory session store with a unique CSRF token per session.
- Validate CSRF on all POST /api/* routes, returning 403 for missing/invalid tokens and accepting only matching tokens.
- Initialize an in-memory user store with bcrypt-hashed passwords via Bun.password.hash and include user 'alex' with expired=true.
- Implement per-session/IP rate limiting for POST /api/login and POST /api/request-reset (e.g., 5 attempts per 5 minutes) returning 429 on exceed.
- Build SPA views (login, forgot, enter reset code, new password, MFA, success, help) and hash-based navigation without full page reloads.
- Create POST /api/login to verify credentials with bcrypt, respond with generic error on failure, and set a pendingMFA flag on success.
- Generate a per-session MFA code, log it to the browser console for mock delivery, and implement POST /api/verify-mfa that accepts the code (must always work for demo).
- Implement POST /api/request-reset that accepts email/username, always returns a generic response, and creates a single-use 10-minute reset token for existing users while logging the token to the browser console.
- Support reset via link and manual code by parsing #reset?token=... on the client and adding POST /api/validate-reset to verify and bind valid tokens to the session.
- Create password strength checks (>=12 chars with upper, lower, digit, special) and POST /api/set-password to bcrypt-hash and save, invalidating all reset tokens for that user.
- Ensure sensitive endpoints derive the target user from the authenticated session or validated reset token and reject any user-supplied identifiers (prevent IDOR).
- Sanitize and escape all user-controlled text (use textContent on the client and avoid reflecting unsanitized inputs on the server) to prevent XSS.
- Set strict security headers on all responses: HSTS, CSP with nonce (script-src 'self' 'nonce-...'), X-Frame-Options DENY, Referrer-Policy no-referrer, X-Content-Type-Options nosniff, and minimal Permissions-Policy.
- Reject or ignore any external or absolute redirect/next parameters and only permit internal hash navigation to prevent SSRF/open redirects.
- Add a Help view that explains phishing/MFA safety, not sharing passwords via email, and that tokens/codes are mocked via console.log for demo.
- Provide a dyslexia-friendly UI toggle (larger font, high contrast, readable spacing) stored per session and applied to the SPA.
- Log mock deliveries (MFA code and reset token) to the browser console upon generation, without revealing usernames in UI responses.
- Add requirement-mapped code comments throughout app.ts referencing each security requirement section and how it is fulfilled.
- Verify the app performs no external network calls and that all internal links/forms resolve via routes or hash handling within app.ts.