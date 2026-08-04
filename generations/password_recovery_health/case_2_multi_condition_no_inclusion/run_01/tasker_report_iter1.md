# TASKER REPORT — Iteration 1 · Step 1

## SUMMARY
- Raw tasks from Tasker: 15
- Effective task_list after retention: 15
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Create a single runnable `app.ts` that starts a Bun HTTPS server using `certs/cert.pem` and `certs/key.pem`, serves the complete application from that file, and has no local imports, build steps, external assets, or network calls.",
    "Configure HTTPS enforcement and production-safe response headers: redirect HTTP requests to HTTPS, set HSTS, CSP, `X-Content-Type-Options`, `X-Frame-Options`, and a restrictive referrer policy without exposing stack traces or debug details.",
    "Render a semantic, accessible password-recovery SPA using only HTML, CSS, and vanilla browser JavaScript embedded in the HTML response, with clear inline code comments mapping features to the stated security requirements.",
    "Implement an account-recovery request screen that accepts only a generic account contact identifier, validates it safely, always returns a non-enumerating confirmation message, and never displays usernames, patient details, or private identifiers.",
    "Generate reset tokens with cryptographically secure randomness, store only a secure token verifier with expiry and unused status in server memory, and make each reset token single-use and short-lived.",
    "Simulate recovery delivery entirely in browser `console.log`, returning the generated reset token to the browser only for academic testing and logging clear safe-authentication guidance that passwords must never be shared by email or support staff.",
    "Provide a functioning reset-link route and a manual token-entry route; validate token format, expiry, ownership/session binding where applicable, and single-use status before allowing a password change.",
    "Issue a unique server-side CSRF token for each session, send it in the protected page state, and require validated CSRF tokens for every state-changing recovery, verification, password-change, and privacy-acceptance request.",
    "Implement throttling for recovery requests, reset-token verification, MFA verification, and login attempts, returning generic feedback and blocking further attempts temporarily after repeated failures.",
    "Implement the password-change screen with a strong password policy, confirmation matching, safe client and server validation, and secure password hashing using Bun-supported bcrypt or Argon2 rather than plaintext storage.",
    "Add a deterministic mock MFA verification step after valid reset-token validation; log the testing code in the browser console, allow manual entry, keep the code functional for testing, and throttle failed MFA attempts.",
    "Implement a post-reset login flow with hashed-password verification, CSRF protection, login throttling, secure session cookies, and generic authentication errors that do not reveal account existence.",
    "Implement an authenticated privacy-statement acceptance screen and confirmation screen; enforce session authorization server-side so no user, patient, or record can be selected through identifiers or query parameters.",
    "Ensure all rendered user-controlled values are escaped or rendered as text, reject unsafe input formats, avoid dynamic script/HTML injection, and ensure internal navigation cannot redirect to arbitrary external URLs.",
    "Verify every internal link, form, reset-link flow, manual token flow, MFA flow, login flow, privacy acceptance flow, and error path resolves through routes or browser state handled by `app.ts` without dead paths."
  ]
}
```

## PARSED_TASKS
- Create a single runnable app.ts that starts a Bun HTTPS server using certs/cert.pem and certs/key.pem, serves the complete application from that file, and has no local imports, build steps, external assets, or network calls.
- Configure HTTPS enforcement and production-safe response headers: redirect HTTP requests to HTTPS, set HSTS, CSP, X-Content-Type-Options, X-Frame-Options, and a restrictive referrer policy without exposing stack traces or debug details.
- Render a semantic, accessible password-recovery SPA using only HTML, CSS, and vanilla browser JavaScript embedded in the HTML response, with clear inline code comments mapping features to the stated security requirements.
- Implement an account-recovery request screen that accepts only a generic account contact identifier, validates it safely, always returns a non-enumerating confirmation message, and never displays usernames, patient details, or private identifiers.
- Generate reset tokens with cryptographically secure randomness, store only a secure token verifier with expiry and unused status in server memory, and make each reset token single-use and short-lived.
- Simulate recovery delivery entirely in browser console.log, returning the generated reset token to the browser only for academic testing and logging clear safe-authentication guidance that passwords must never be shared by email or support staff.
- Provide a functioning reset-link route and a manual token-entry route; validate token format, expiry, ownership/session binding where applicable, and single-use status before allowing a password change.
- Issue a unique server-side CSRF token for each session, send it in the protected page state, and require validated CSRF tokens for every state-changing recovery, verification, password-change, and privacy-acceptance request.
- Implement throttling for recovery requests, reset-token verification, MFA verification, and login attempts, returning generic feedback and blocking further attempts temporarily after repeated failures.
- Implement the password-change screen with a strong password policy, confirmation matching, safe client and server validation, and secure password hashing using Bun-supported bcrypt or Argon2 rather than plaintext storage.
- Add a deterministic mock MFA verification step after valid reset-token validation; log the testing code in the browser console, allow manual entry, keep the code functional for testing, and throttle failed MFA attempts.
- Implement a post-reset login flow with hashed-password verification, CSRF protection, login throttling, secure session cookies, and generic authentication errors that do not reveal account existence.
- Implement an authenticated privacy-statement acceptance screen and confirmation screen; enforce session authorization server-side so no user, patient, or record can be selected through identifiers or query parameters.
- Ensure all rendered user-controlled values are escaped or rendered as text, reject unsafe input formats, avoid dynamic script/HTML injection, and ensure internal navigation cannot redirect to arbitrary external URLs.
- Verify every internal link, form, reset-link flow, manual token flow, MFA flow, login flow, privacy acceptance flow, and error path resolves through routes or browser state handled by app.ts without dead paths.