# TASKER REPORT — Iteration 1 · Step 1

## SUMMARY
- Raw tasks from Tasker: 14
- Effective task_list after retention: 14
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Create a single runnable `app.ts` Bun application that serves the complete HTML, CSS, and vanilla-JavaScript mobile SPA, with no local modules, build steps, frameworks, external assets, or network calls.",
    "Configure the Bun server to use `certs/cert.pem` and `certs/key.pem` for HTTPS, reject non-secure traffic as appropriate, and provide a generic production-safe error response without stack traces.",
    "Add security headers to every response: restrictive CSP, HSTS, `X-Content-Type-Options: nosniff`, clickjacking protection (`frame-ancestors` and/or `X-Frame-Options`), and CORS restricted to the local trusted origin.",
    "Implement secure session authentication using server-side in-memory session state and an HttpOnly, Secure, SameSite cookie; rotate the session identifier after authentication, enforce idle and absolute expiry, and invalidate it on logout.",
    "Implement server-side authorization for every MFA route so the current session can access and modify only its own account’s MFA state, ignoring or rejecting guessed or manipulated account identifiers.",
    "Implement CSRF protection for every state-changing MFA operation, including authenticator enrollment verification, MFA enablement, recovery-code use, and recovery-code regeneration.",
    "Build a responsive, semantic mobile enrollment flow covering sign-in, identity verification, authenticator setup, OTP confirmation, recovery-code display, MFA settings, recovery-code regeneration, and logout.",
    "Generate authenticator secrets, verification challenges, session IDs, CSRF tokens, and recovery codes with cryptographically secure randomness; store authenticator secrets encrypted or strongly protected at rest and store recovery codes only as strong hashes.",
    "Simulate authenticator provisioning with a deterministic working verification code and provide a manual secret/code entry path; display provisioning details only in the UI and log the mock delivery details only to the browser console.",
    "Implement verification-code rules: single use, time-bound validity, sufficient entropy, failed-attempt rate limiting and lockout, and generic failure messages that do not enable user enumeration.",
    "Validate all server-side inputs for email, phone, OTP, CSRF token, and recovery code; use safe data access patterns and contextual output escaping so user-controlled values cannot produce injection or XSS.",
    "Ensure client logic never stores secrets, OTPs, recovery codes, or session tokens in localStorage, sessionStorage, URL query strings, or non-HttpOnly cookies, and ensure server logs and error responses never expose them.",
    "Restrict any client/server redirect target to an internal allow-list and verify that every navigation link, form submission, and SPA route resolves to a working in-app screen.",
    "Add concise code comments in `app.ts` mapping the relevant implementation sections to each security requirement category and the one-file, browser-console mock, and mobile UI requirements."
  ]
}
```

## PARSED_TASKS
- Create a single runnable app.ts Bun application that serves the complete HTML, CSS, and vanilla-JavaScript mobile SPA, with no local modules, build steps, frameworks, external assets, or network calls.
- Configure the Bun server to use certs/cert.pem and certs/key.pem for HTTPS, reject non-secure traffic as appropriate, and provide a generic production-safe error response without stack traces.
- Add security headers to every response: restrictive CSP, HSTS, X-Content-Type-Options: nosniff, clickjacking protection (frame-ancestors and/or X-Frame-Options), and CORS restricted to the local trusted origin.
- Implement secure session authentication using server-side in-memory session state and an HttpOnly, Secure, SameSite cookie; rotate the session identifier after authentication, enforce idle and absolute expiry, and invalidate it on logout.
- Implement server-side authorization for every MFA route so the current session can access and modify only its own account’s MFA state, ignoring or rejecting guessed or manipulated account identifiers.
- Implement CSRF protection for every state-changing MFA operation, including authenticator enrollment verification, MFA enablement, recovery-code use, and recovery-code regeneration.
- Build a responsive, semantic mobile enrollment flow covering sign-in, identity verification, authenticator setup, OTP confirmation, recovery-code display, MFA settings, recovery-code regeneration, and logout.
- Generate authenticator secrets, verification challenges, session IDs, CSRF tokens, and recovery codes with cryptographically secure randomness; store authenticator secrets encrypted or strongly protected at rest and store recovery codes only as strong hashes.
- Simulate authenticator provisioning with a deterministic working verification code and provide a manual secret/code entry path; display provisioning details only in the UI and log the mock delivery details only to the browser console.
- Implement verification-code rules: single use, time-bound validity, sufficient entropy, failed-attempt rate limiting and lockout, and generic failure messages that do not enable user enumeration.
- Validate all server-side inputs for email, phone, OTP, CSRF token, and recovery code; use safe data access patterns and contextual output escaping so user-controlled values cannot produce injection or XSS.
- Ensure client logic never stores secrets, OTPs, recovery codes, or session tokens in localStorage, sessionStorage, URL query strings, or non-HttpOnly cookies, and ensure server logs and error responses never expose them.
- Restrict any client/server redirect target to an internal allow-list and verify that every navigation link, form submission, and SPA route resolves to a working in-app screen.
- Add concise code comments in app.ts mapping the relevant implementation sections to each security requirement category and the one-file, browser-console mock, and mobile UI requirements.