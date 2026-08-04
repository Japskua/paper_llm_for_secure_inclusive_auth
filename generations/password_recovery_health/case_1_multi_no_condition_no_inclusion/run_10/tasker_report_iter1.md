# TASKER REPORT — Iteration 1 · Step 1

## SUMMARY
- Raw tasks from Tasker: 10
- Effective task_list after retention: 10
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Create a single runnable `app.ts` Bun HTTPS server that uses `certs/cert.pem` and `certs/key.pem`, serves the complete inline HTML/CSS/vanilla-JS SPA, and handles all application routes without external files or network calls.",
    "Implement secure response headers and HTTPS-only behavior: redirect HTTP requests to HTTPS, configure HSTS, CSP, clickjacking protection, MIME sniffing protection, referrer policy, and non-debug error responses.",
    "Add server-side in-memory session management with cryptographically random Secure, HttpOnly, SameSite cookies and a unique CSRF token per session; require and validate the CSRF token for every state-changing endpoint.",
    "Implement a privacy-preserving reset-request endpoint that accepts a sanitized account identifier, always returns a generic confirmation, rate-limits repeated requests, creates a cryptographically random short-lived single-use reset token only for the mock account, and logs simulated delivery without exposing patient data.",
    "Implement a reset verification endpoint that validates token existence, expiry, single-use status, session association, CSRF token, and throttled attempt limits; return only safe generic errors and support manual token submission.",
    "Implement password-reset completion with server-side strong-password validation, non-plaintext password storage using Bun-supported bcrypt or Argon2 hashing, reset-token invalidation, and safe success feedback.",
    "Implement a mock MFA step after password reset using a deterministic code that is logged in the browser console, remains valid for testing, is rate-limited, and is required before creating an authenticated session.",
    "Build the accessible semantic recovery UI with screens for reset request, manual token verification, new password, MFA verification, privacy-conditions confirmation, and completion; make all navigation and forms function through the SPA or app.ts routes.",
    "Ensure client-side rendering treats all server and user-controlled values as text rather than HTML, validates inputs only as usability support, avoids dynamic script injection and redirects, and logs all mocked delivery/authentication actions only in the browser console.",
    "Add concise comments in `app.ts` mapping each security control and recovery-flow component to the applicable numbered requirements, including CSRF/access control, XSS prevention, HTTPS/token security, authentication throttling/password hashing/MFA, and phishing/open-redirect guidance."
  ]
}
```

## PARSED_TASKS
- Create a single runnable app.ts Bun HTTPS server that uses certs/cert.pem and certs/key.pem, serves the complete inline HTML/CSS/vanilla-JS SPA, and handles all application routes without external files or network calls.
- Implement secure response headers and HTTPS-only behavior: redirect HTTP requests to HTTPS, configure HSTS, CSP, clickjacking protection, MIME sniffing protection, referrer policy, and non-debug error responses.
- Add server-side in-memory session management with cryptographically random Secure, HttpOnly, SameSite cookies and a unique CSRF token per session; require and validate the CSRF token for every state-changing endpoint.
- Implement a privacy-preserving reset-request endpoint that accepts a sanitized account identifier, always returns a generic confirmation, rate-limits repeated requests, creates a cryptographically random short-lived single-use reset token only for the mock account, and logs simulated delivery without exposing patient data.
- Implement a reset verification endpoint that validates token existence, expiry, single-use status, session association, CSRF token, and throttled attempt limits; return only safe generic errors and support manual token submission.
- Implement password-reset completion with server-side strong-password validation, non-plaintext password storage using Bun-supported bcrypt or Argon2 hashing, reset-token invalidation, and safe success feedback.
- Implement a mock MFA step after password reset using a deterministic code that is logged in the browser console, remains valid for testing, is rate-limited, and is required before creating an authenticated session.
- Build the accessible semantic recovery UI with screens for reset request, manual token verification, new password, MFA verification, privacy-conditions confirmation, and completion; make all navigation and forms function through the SPA or app.ts routes.
- Ensure client-side rendering treats all server and user-controlled values as text rather than HTML, validates inputs only as usability support, avoids dynamic script injection and redirects, and logs all mocked delivery/authentication actions only in the browser console.
- Add concise comments in app.ts mapping each security control and recovery-flow component to the applicable numbered requirements, including CSRF/access control, XSS prevention, HTTPS/token security, authentication throttling/password hashing/MFA, and phishing/open-redirect guidance.