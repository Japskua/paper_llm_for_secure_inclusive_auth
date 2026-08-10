# TASKER REPORT — Iteration 1 · Step 1

## SUMMARY
- Raw tasks from Tasker: 12
- Effective task_list after retention: 12
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Create a single runnable `app.ts` Bun HTTPS server that serves the complete application from one inline HTML/CSS/vanilla-JavaScript template and uses `certs/cert.pem` plus `certs/key.pem`.",
    "Configure HTTPS enforcement and production-safe response headers, including HSTS, restrictive CSP, frame protection, MIME sniffing protection, referrer policy, and no-cache handling for sensitive pages.",
    "Implement a semantic single-page password-recovery interface with reachable stages for account recovery request, reset-token verification (including manual entry), new password creation, MFA verification, privacy-condition acceptance, and confirmation.",
    "Implement in-memory per-session state with Secure, HttpOnly, SameSite cookies and a unique CSRF token; require and validate the CSRF token for every state-changing route.",
    "Add recovery-request handling that accepts a minimally identifying account input, returns only generic anti-enumeration feedback, generates a cryptographically random reset token, expires it shortly, marks it single-use, and logs the mock delivery token in the browser console.",
    "Implement secure reset-token validation that accepts both the simulated reset-link route and manual token submission, rejects expired, invalid, reused, or session-mismatched tokens, and rate-limits repeated verification failures.",
    "Implement password replacement with a clear strong-password policy, server-side validation, non-plaintext password storage using Bun-supported bcrypt or Argon2 hashing, token invalidation after successful use, and browser-console mock logging only.",
    "Implement deterministic simulated MFA after password reset, with browser-console delivery logging, valid-code handling, attempt throttling, and no expiry that would prevent the supplied mock code from working.",
    "Protect privacy-condition acceptance and confirmation routes with authenticated session and completed-MFA checks, ensuring users can only read or modify their own in-memory session state.",
    "Sanitize and safely render all user-controlled values without HTML interpolation, avoid untrusted inline script execution, validate all route/query inputs and redirect targets against an internal allowlist, and provide safe-authentication guidance warning users never to share passwords or codes.",
    "Add concise source comments in `app.ts` mapping the server, client flow, input handling, session/CSRF controls, headers, reset tokens, password hashing, MFA, throttling, and anti-phishing controls to the numbered security requirements.",
    "Ensure all application routes, forms, links, error states, and confirmation navigation are handled within `app.ts`, make no external network requests, and avoid exposing debug output, stack traces, usernames, patient data, or private identifiers in responses."
  ]
}
```

## PARSED_TASKS
- Create a single runnable app.ts Bun HTTPS server that serves the complete application from one inline HTML/CSS/vanilla-JavaScript template and uses certs/cert.pem plus certs/key.pem.
- Configure HTTPS enforcement and production-safe response headers, including HSTS, restrictive CSP, frame protection, MIME sniffing protection, referrer policy, and no-cache handling for sensitive pages.
- Implement a semantic single-page password-recovery interface with reachable stages for account recovery request, reset-token verification (including manual entry), new password creation, MFA verification, privacy-condition acceptance, and confirmation.
- Implement in-memory per-session state with Secure, HttpOnly, SameSite cookies and a unique CSRF token; require and validate the CSRF token for every state-changing route.
- Add recovery-request handling that accepts a minimally identifying account input, returns only generic anti-enumeration feedback, generates a cryptographically random reset token, expires it shortly, marks it single-use, and logs the mock delivery token in the browser console.
- Implement secure reset-token validation that accepts both the simulated reset-link route and manual token submission, rejects expired, invalid, reused, or session-mismatched tokens, and rate-limits repeated verification failures.
- Implement password replacement with a clear strong-password policy, server-side validation, non-plaintext password storage using Bun-supported bcrypt or Argon2 hashing, token invalidation after successful use, and browser-console mock logging only.
- Implement deterministic simulated MFA after password reset, with browser-console delivery logging, valid-code handling, attempt throttling, and no expiry that would prevent the supplied mock code from working.
- Protect privacy-condition acceptance and confirmation routes with authenticated session and completed-MFA checks, ensuring users can only read or modify their own in-memory session state.
- Sanitize and safely render all user-controlled values without HTML interpolation, avoid untrusted inline script execution, validate all route/query inputs and redirect targets against an internal allowlist, and provide safe-authentication guidance warning users never to share passwords or codes.
- Add concise source comments in app.ts mapping the server, client flow, input handling, session/CSRF controls, headers, reset tokens, password hashing, MFA, throttling, and anti-phishing controls to the numbered security requirements.
- Ensure all application routes, forms, links, error states, and confirmation navigation are handled within app.ts, make no external network requests, and avoid exposing debug output, stack traces, usernames, patient data, or private identifiers in responses.