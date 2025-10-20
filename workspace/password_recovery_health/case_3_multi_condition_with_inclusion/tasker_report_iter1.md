# TASKER REPORT — Iteration 1 · Step 1

## SUMMARY
- Raw tasks from Tasker: 25
- Effective task_list after retention: 25
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Start an HTTPS Bun server using certs/cert.pem and certs/key.pem that serves the SPA HTML at GET /.",
    "Return strict security headers on all responses (HSTS, CSP with nonce, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy).",
    "Implement a catch-all GET handler that serves the same SPA HTML for unknown paths to avoid broken links.",
    "Create in-memory stores for users, sessions, reset tokens, MFA codes, and rate limits (non-persistent).",
    "Seed one demo user with an email and a password hashed using Bun.password.hash (bcrypt or argon2id).",
    "Create session management with a signed, HttpOnly, Secure, SameSite=Strict cookie and per-session CSRF token.",
    "Render an accessible, low-distraction SPA with a step-by-step password reset wizard and progress indicator.",
    "Include a persistent Help & Safety panel accessible from every step with phishing and safety tips.",
    "Persist wizard progress and minimal form data in localStorage so reload resumes the same step.",
    "Implement client-side CSRF inclusion on all sensitive requests and server-side CSRF validation (403 on failure).",
    "Add a password reset request endpoint that rate-limits by IP and account and returns a masked success message.",
    "Generate a cryptographically random reset token (single-use until used) and store it server-side with the account.",
    "Derive a deterministic short verification code from the reset token (e.g., hash-based) and store it for manual entry.",
    "Return to the browser (and console.log) the reset verification link (with token) and the short manual code.",
    "Add a verification endpoint that accepts either the token (link) or the short code and establishes a reset session.",
    "Generate an MFA code (deterministic for demo) on verification; display it via console.log and accept manual entry.",
    "Throttle verification and MFA submission attempts and return 429 with Retry-After on excess.",
    "Enforce a strong password policy on client and server (min length, character variety, and common-password checks).",
    "Add a password update endpoint that requires a valid reset session and CSRF, then hashes and saves the new password.",
    "Invalidate used reset tokens, MFA codes, and prior sessions on successful password update.",
    "Provide a simple login UI and endpoint with CSRF, hashing verification, throttling, and optional MFA.",
    "Sanitize and escape any user-displayed input and ensure CSP nonce-based scripts only (no inline event handlers).",
    "Reject open redirects by validating/whitelisting any redirect targets used after login or reset.",
    "Log all mocked deliveries (reset link, manual code, MFA code) to the browser console as required.",
    "Add code comments mapping each implemented section back to the listed Security and Inclusivity requirements"
  ]
}
```

## PARSED_TASKS
- Start an HTTPS Bun server using certs/cert.pem and certs/key.pem that serves the SPA HTML at GET /.
- Return strict security headers on all responses (HSTS, CSP with nonce, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy).
- Implement a catch-all GET handler that serves the same SPA HTML for unknown paths to avoid broken links.
- Create in-memory stores for users, sessions, reset tokens, MFA codes, and rate limits (non-persistent).
- Seed one demo user with an email and a password hashed using Bun.password.hash (bcrypt or argon2id).
- Create session management with a signed, HttpOnly, Secure, SameSite=Strict cookie and per-session CSRF token.
- Render an accessible, low-distraction SPA with a step-by-step password reset wizard and progress indicator.
- Include a persistent Help & Safety panel accessible from every step with phishing and safety tips.
- Persist wizard progress and minimal form data in localStorage so reload resumes the same step.
- Implement client-side CSRF inclusion on all sensitive requests and server-side CSRF validation (403 on failure).
- Add a password reset request endpoint that rate-limits by IP and account and returns a masked success message.
- Generate a cryptographically random reset token (single-use until used) and store it server-side with the account.
- Derive a deterministic short verification code from the reset token (e.g., hash-based) and store it for manual entry.
- Return to the browser (and console.log) the reset verification link (with token) and the short manual code.
- Add a verification endpoint that accepts either the token (link) or the short code and establishes a reset session.
- Generate an MFA code (deterministic for demo) on verification; display it via console.log and accept manual entry.
- Throttle verification and MFA submission attempts and return 429 with Retry-After on excess.
- Enforce a strong password policy on client and server (min length, character variety, and common-password checks).
- Add a password update endpoint that requires a valid reset session and CSRF, then hashes and saves the new password.
- Invalidate used reset tokens, MFA codes, and prior sessions on successful password update.
- Provide a simple login UI and endpoint with CSRF, hashing verification, throttling, and optional MFA.
- Sanitize and escape any user-displayed input and ensure CSP nonce-based scripts only (no inline event handlers).
- Reject open redirects by validating/whitelisting any redirect targets used after login or reset.
- Log all mocked deliveries (reset link, manual code, MFA code) to the browser console as required.
- Add code comments mapping each implemented section back to the listed Security and Inclusivity requirements