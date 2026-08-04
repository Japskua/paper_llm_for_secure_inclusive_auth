# TASKER REPORT — Iteration 1 · Step 1

## SUMMARY
- Raw tasks from Tasker: 13
- Effective task_list after retention: 13
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Create a single runnable `app.ts` Bun HTTPS server that serves the complete password-recovery SPA, uses `certs/cert.pem` and `certs/key.pem`, and has no local modules, build steps, frameworks, external assets, or external network requests.",
    "Configure HTTPS-only security behavior: redirect or reject insecure HTTP requests, set HSTS, restrictive CSP with a per-response nonce, and appropriate no-sniff, frame-ancestors, referrer, cache-control, and permissions-policy headers without exposing debug details.",
    "Implement server-side in-memory session handling with cryptographically random session IDs, Secure/HttpOnly/SameSite cookies, session-bound cryptographically random CSRF tokens, and CSRF validation for every state-changing endpoint.",
    "Create semantic, accessible plain HTML/CSS recovery screens for account recovery request, reset-token verification/manual token entry, password reset, MFA confirmation, privacy-condition acceptance, and successful appointment-request confirmation.",
    "Implement client-side navigation so every recovery-flow link, form, and confirmation view works within the SPA without dead paths, unsafe redirects, or external destinations.",
    "Implement a generic recovery-request endpoint that accepts an account identifier without revealing whether an account exists, validates input, rate-limits repeated attempts, and logs deterministic mock reset delivery details only in the browser console.",
    "Generate reset tokens with cryptographically secure randomness; bind each token to its requesting session and mock account, enforce short expiry and single use, and return the test token to the browser only for browser-console mock delivery.",
    "Implement secure reset-token verification that supports both a simulated verification-link route/query flow and manual code submission, rejects invalid, expired, reused, or session-mismatched tokens with clear non-sensitive feedback, and throttles guessing attempts.",
    "Implement password-reset submission with a strong password policy, confirmation matching, server-side validation, password hashing using Bun-supported bcrypt or Argon2 functionality, and no plaintext password persistence or logging.",
    "Implement a deterministic mock MFA step after password reset, display its test code only through browser console logging, ensure valid codes always work, and throttle repeated invalid MFA attempts.",
    "Implement authenticated privacy-condition acceptance and the final simulated appointment-booking confirmation; require the current session’s completed reset/MFA state, validate CSRF, prevent IDOR, and log simulated actions only in the browser console.",
    "Ensure all client-rendered dynamic text is inserted as text rather than HTML, validate and sanitize all request inputs server-side, and ensure no user-controlled input can execute script, create a redirect, or expose private identifiers.",
    "Add concise code comments in `app.ts` mapping the HTTPS, headers, CSRF, access-control, escaping, token, password, MFA, throttling, phishing-awareness, and mock-delivery logic to the corresponding numbered security requirements."
  ]
}
```

## PARSED_TASKS
- Create a single runnable app.ts Bun HTTPS server that serves the complete password-recovery SPA, uses certs/cert.pem and certs/key.pem, and has no local modules, build steps, frameworks, external assets, or external network requests.
- Configure HTTPS-only security behavior: redirect or reject insecure HTTP requests, set HSTS, restrictive CSP with a per-response nonce, and appropriate no-sniff, frame-ancestors, referrer, cache-control, and permissions-policy headers without exposing debug details.
- Implement server-side in-memory session handling with cryptographically random session IDs, Secure/HttpOnly/SameSite cookies, session-bound cryptographically random CSRF tokens, and CSRF validation for every state-changing endpoint.
- Create semantic, accessible plain HTML/CSS recovery screens for account recovery request, reset-token verification/manual token entry, password reset, MFA confirmation, privacy-condition acceptance, and successful appointment-request confirmation.
- Implement client-side navigation so every recovery-flow link, form, and confirmation view works within the SPA without dead paths, unsafe redirects, or external destinations.
- Implement a generic recovery-request endpoint that accepts an account identifier without revealing whether an account exists, validates input, rate-limits repeated attempts, and logs deterministic mock reset delivery details only in the browser console.
- Generate reset tokens with cryptographically secure randomness; bind each token to its requesting session and mock account, enforce short expiry and single use, and return the test token to the browser only for browser-console mock delivery.
- Implement secure reset-token verification that supports both a simulated verification-link route/query flow and manual code submission, rejects invalid, expired, reused, or session-mismatched tokens with clear non-sensitive feedback, and throttles guessing attempts.
- Implement password-reset submission with a strong password policy, confirmation matching, server-side validation, password hashing using Bun-supported bcrypt or Argon2 functionality, and no plaintext password persistence or logging.
- Implement a deterministic mock MFA step after password reset, display its test code only through browser console logging, ensure valid codes always work, and throttle repeated invalid MFA attempts.
- Implement authenticated privacy-condition acceptance and the final simulated appointment-booking confirmation; require the current session’s completed reset/MFA state, validate CSRF, prevent IDOR, and log simulated actions only in the browser console.
- Ensure all client-rendered dynamic text is inserted as text rather than HTML, validate and sanitize all request inputs server-side, and ensure no user-controlled input can execute script, create a redirect, or expose private identifiers.
- Add concise code comments in app.ts mapping the HTTPS, headers, CSRF, access-control, escaping, token, password, MFA, throttling, phishing-awareness, and mock-delivery logic to the corresponding numbered security requirements.