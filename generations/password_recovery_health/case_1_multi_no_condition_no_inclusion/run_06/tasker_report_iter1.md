# TASKER REPORT — Iteration 1 · Step 1

## SUMMARY
- Raw tasks from Tasker: 15
- Effective task_list after retention: 15
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Create a single runnable `app.ts` Bun application that serves the complete password-recovery SPA with all HTML, CSS, and vanilla browser JavaScript embedded inline.",
    "Configure the Bun server to use `certs/cert.pem` and `certs/key.pem`, redirect HTTP requests to HTTPS, and return security headers including HSTS, a restrictive CSP, frame protection, MIME sniffing protection, and referrer policy.",
    "Implement session creation using cryptographically secure, HttpOnly, Secure, SameSite cookies and server-side in-memory session state without exposing patient names, usernames, or identifiers in responses.",
    "Generate a unique cryptographically secure CSRF token for each session, include it in the SPA bootstrap data, and validate it for every state-changing endpoint.",
    "Implement a privacy-preserving password-reset request endpoint that accepts an account recovery identifier, returns a generic confirmation message, and never reveals whether an account exists.",
    "Generate cryptographically random, single-use, short-lived reset tokens stored only in server-side state; simulate delivery by returning the test token to the browser solely for `console.log` output.",
    "Implement reset-token verification that accepts both a reset-link token and manual code entry, rejects expired, reused, malformed, or brute-forced tokens, and returns clear non-sensitive feedback.",
    "Add rate limiting for password-reset requests, token verification attempts, and login attempts using server-side in-memory counters keyed without exposing private account details.",
    "Implement password replacement requiring a strong password policy, confirmation matching, secure server-side validation, and hashing with Bun-supported bcrypt or Argon2 before storing the replacement credential.",
    "Implement MFA verification after successful password reset using a deterministic mock code that always works, log simulated delivery only in the browser console, and throttle invalid MFA attempts.",
    "Implement an authenticated privacy-conditions acceptance endpoint that requires the validated session, CSRF token, and completed MFA state, and prevents access through guessed identifiers or request parameters.",
    "Build accessible semantic SPA screens for recovery request, reset delivery confirmation, link-or-code verification, new password entry, MFA, privacy acceptance, and completion, with all navigation handled by defined in-app routes or state.",
    "Ensure every browser-rendered dynamic value is inserted as text rather than HTML, validate input formats and lengths on both client and server, and avoid executing user-controlled content or redirects.",
    "Display clear anti-phishing and social-engineering guidance in the recovery flow, including that hospital staff will not request passwords or codes and that users should verify the localhost HTTPS address.",
    "Add concise code comments in `app.ts` mapping the server, session, CSRF, token, authentication, XSS prevention, HTTPS, rate-limit, and safe-navigation logic to the numbered security requirements."
  ]
}
```

## PARSED_TASKS
- Create a single runnable app.ts Bun application that serves the complete password-recovery SPA with all HTML, CSS, and vanilla browser JavaScript embedded inline.
- Configure the Bun server to use certs/cert.pem and certs/key.pem, redirect HTTP requests to HTTPS, and return security headers including HSTS, a restrictive CSP, frame protection, MIME sniffing protection, and referrer policy.
- Implement session creation using cryptographically secure, HttpOnly, Secure, SameSite cookies and server-side in-memory session state without exposing patient names, usernames, or identifiers in responses.
- Generate a unique cryptographically secure CSRF token for each session, include it in the SPA bootstrap data, and validate it for every state-changing endpoint.
- Implement a privacy-preserving password-reset request endpoint that accepts an account recovery identifier, returns a generic confirmation message, and never reveals whether an account exists.
- Generate cryptographically random, single-use, short-lived reset tokens stored only in server-side state; simulate delivery by returning the test token to the browser solely for console.log output.
- Implement reset-token verification that accepts both a reset-link token and manual code entry, rejects expired, reused, malformed, or brute-forced tokens, and returns clear non-sensitive feedback.
- Add rate limiting for password-reset requests, token verification attempts, and login attempts using server-side in-memory counters keyed without exposing private account details.
- Implement password replacement requiring a strong password policy, confirmation matching, secure server-side validation, and hashing with Bun-supported bcrypt or Argon2 before storing the replacement credential.
- Implement MFA verification after successful password reset using a deterministic mock code that always works, log simulated delivery only in the browser console, and throttle invalid MFA attempts.
- Implement an authenticated privacy-conditions acceptance endpoint that requires the validated session, CSRF token, and completed MFA state, and prevents access through guessed identifiers or request parameters.
- Build accessible semantic SPA screens for recovery request, reset delivery confirmation, link-or-code verification, new password entry, MFA, privacy acceptance, and completion, with all navigation handled by defined in-app routes or state.
- Ensure every browser-rendered dynamic value is inserted as text rather than HTML, validate input formats and lengths on both client and server, and avoid executing user-controlled content or redirects.
- Display clear anti-phishing and social-engineering guidance in the recovery flow, including that hospital staff will not request passwords or codes and that users should verify the localhost HTTPS address.
- Add concise code comments in app.ts mapping the server, session, CSRF, token, authentication, XSS prevention, HTTPS, rate-limit, and safe-navigation logic to the numbered security requirements.