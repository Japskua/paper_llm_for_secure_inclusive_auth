# TASKER REPORT — Iteration 1 · Step 1

## SUMMARY
- Raw tasks from Tasker: 14
- Effective task_list after retention: 14
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Create a single runnable `app.ts` Bun HTTPS server that loads `certs/cert.pem` and `certs/key.pem`, serves the mobile SPA, and provides generic production-safe error responses without debug details.",
    "Add secure response configuration for every route: HTTPS enforcement, HSTS, restrictive CSP with clickjacking protection, `X-Content-Type-Options: nosniff`, and CORS limited to the local trusted origin.",
    "Implement in-memory authenticated session handling with cryptographically random HttpOnly, Secure, SameSite cookies; rotate sessions at authentication, enforce idle and absolute expiry, and invalidate sessions on logout.",
    "Implement server-side authorization middleware on every MFA route that derives the account solely from the session and rejects absent, expired, or mismatched user identifiers without revealing account existence.",
    "Implement CSRF token generation and validation for every state-changing MFA request, requiring a valid session-bound token before enrollment, verification, recovery-code regeneration, or logout changes state.",
    "Implement validated server endpoints for the enrollment flow: authenticated identity confirmation, authenticator setup, OTP verification, MFA status, recovery-code display, recovery-code regeneration, and logout.",
    "Generate authenticator secrets, OTP challenges, and recovery codes with cryptographically secure randomness; protect stored authenticator secrets and recovery codes at rest using appropriate encryption or one-way hashing.",
    "Make OTP and recovery-code verification single-use and time-bound, with per-session/account attempt rate limiting and temporary lockout after repeated failures; return non-enumerating generic failure messages.",
    "Validate all request inputs on the server (including email, phone, OTP, recovery code, CSRF token, and redirects), allow redirects only to approved internal paths, and ensure no sensitive values appear in URLs, server errors, or server logs.",
    "Return one responsive semantic HTML page from `app.ts` containing only inline CSS and vanilla browser JavaScript, with mobile-readable views for sign-in/identity confirmation, authenticator setup, OTP verification, MFA confirmation, and recovery-code management.",
    "Implement client-side SPA navigation and form submission for all enrollment routes without external requests, browser storage, frameworks, separate assets, or dead internal links.",
    "For each simulated OTP/provisioning and recovery-code delivery, return the needed test value only through the authenticated UI flow and log it with `console.log` in the browser; never log secrets, OTPs, recovery codes, or session tokens on the server.",
    "Apply safe DOM rendering and contextual output encoding so user-controlled values are never inserted as HTML, and display clear accessible validation, rate-limit, and success states on mobile screens.",
    "Add concise code comments in `app.ts` mapping the server and client controls to each applicable Security Evaluation Requirement section."
  ]
}
```

## PARSED_TASKS
- Create a single runnable app.ts Bun HTTPS server that loads certs/cert.pem and certs/key.pem, serves the mobile SPA, and provides generic production-safe error responses without debug details.
- Add secure response configuration for every route: HTTPS enforcement, HSTS, restrictive CSP with clickjacking protection, X-Content-Type-Options: nosniff, and CORS limited to the local trusted origin.
- Implement in-memory authenticated session handling with cryptographically random HttpOnly, Secure, SameSite cookies; rotate sessions at authentication, enforce idle and absolute expiry, and invalidate sessions on logout.
- Implement server-side authorization middleware on every MFA route that derives the account solely from the session and rejects absent, expired, or mismatched user identifiers without revealing account existence.
- Implement CSRF token generation and validation for every state-changing MFA request, requiring a valid session-bound token before enrollment, verification, recovery-code regeneration, or logout changes state.
- Implement validated server endpoints for the enrollment flow: authenticated identity confirmation, authenticator setup, OTP verification, MFA status, recovery-code display, recovery-code regeneration, and logout.
- Generate authenticator secrets, OTP challenges, and recovery codes with cryptographically secure randomness; protect stored authenticator secrets and recovery codes at rest using appropriate encryption or one-way hashing.
- Make OTP and recovery-code verification single-use and time-bound, with per-session/account attempt rate limiting and temporary lockout after repeated failures; return non-enumerating generic failure messages.
- Validate all request inputs on the server (including email, phone, OTP, recovery code, CSRF token, and redirects), allow redirects only to approved internal paths, and ensure no sensitive values appear in URLs, server errors, or server logs.
- Return one responsive semantic HTML page from app.ts containing only inline CSS and vanilla browser JavaScript, with mobile-readable views for sign-in/identity confirmation, authenticator setup, OTP verification, MFA confirmation, and recovery-code management.
- Implement client-side SPA navigation and form submission for all enrollment routes without external requests, browser storage, frameworks, separate assets, or dead internal links.
- For each simulated OTP/provisioning and recovery-code delivery, return the needed test value only through the authenticated UI flow and log it with console.log in the browser; never log secrets, OTPs, recovery codes, or session tokens on the server.
- Apply safe DOM rendering and contextual output encoding so user-controlled values are never inserted as HTML, and display clear accessible validation, rate-limit, and success states on mobile screens.
- Add concise code comments in app.ts mapping the server and client controls to each applicable Security Evaluation Requirement section.