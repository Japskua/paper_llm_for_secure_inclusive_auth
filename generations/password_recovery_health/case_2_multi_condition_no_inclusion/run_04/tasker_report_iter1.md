# TASKER REPORT — Iteration 1 · Step 1

## SUMMARY
- Raw tasks from Tasker: 14
- Effective task_list after retention: 14
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Create a single runnable `app.ts` that starts a Bun HTTPS server using `certs/cert.pem` and `certs/key.pem`, serves the complete application, and does not import local project files or require a build step.",
    "Configure HTTPS-only security behavior: redirect/reject non-secure requests as applicable, set HSTS, CSP, `X-Content-Type-Options`, `X-Frame-Options`, referrer-policy, and restrictive permissions-policy headers, and return generic error responses without stack traces.",
    "Embed a semantic password-recovery SPA in the server HTML response using only inline HTML, CSS, and vanilla browser JavaScript, with no external assets, frameworks, or remote network calls.",
    "Implement internal client-side routing or state transitions for the recovery request, reset-token verification, new-password entry, MFA verification, and completion screens so every visible internal link and form action works.",
    "Implement a recovery-request form that accepts a non-identifying account contact value, validates it safely, always gives a generic response, and logs simulated recovery delivery plus the deterministic test token in the browser console.",
    "Generate reset tokens server-side using cryptographically secure randomness, bind each token to the requesting session and recovery record, enforce short expiry and single use, and permit the delivered token to be entered manually.",
    "Create per-session CSRF tokens, store them server-side, and require valid CSRF validation for every state-changing recovery, token-verification, password-change, and MFA request.",
    "Enforce access control on recovery and authenticated routes by checking the current session and reset-flow ownership; reject missing, expired, reused, or cross-session tokens without exposing private account data.",
    "Implement rate limiting or temporary lockout for repeated recovery-token, MFA-code, and login/reset-password failures, with clear non-sensitive feedback and no account enumeration.",
    "Implement a strong new-password policy and store only a secure bcrypt or Argon2 password hash in in-memory mock state; never render, log, or retain the submitted plaintext password after processing.",
    "Implement a deterministic simulated MFA step that can be completed by the user, logs its mock delivery only in the browser console, and requires successful MFA before finalizing the password reset.",
    "Sanitize and validate all request inputs, escape all values rendered into HTML, avoid inserting untrusted values through executable DOM APIs, and ensure user input cannot create scripts, redirects, or fake authentication pages.",
    "Restrict all navigation and post-reset destinations to an internal allowlist, and include visible safe-authentication guidance warning users not to share passwords or codes with email, callers, or purported staff.",
    "Add concise code comments in `app.ts` mapping the implementation to each applicable Security Evaluation Requirement section and the single-file/Bun/vanilla-JavaScript delivery constraints."
  ]
}
```

## PARSED_TASKS
- Create a single runnable app.ts that starts a Bun HTTPS server using certs/cert.pem and certs/key.pem, serves the complete application, and does not import local project files or require a build step.
- Configure HTTPS-only security behavior: redirect/reject non-secure requests as applicable, set HSTS, CSP, X-Content-Type-Options, X-Frame-Options, referrer-policy, and restrictive permissions-policy headers, and return generic error responses without stack traces.
- Embed a semantic password-recovery SPA in the server HTML response using only inline HTML, CSS, and vanilla browser JavaScript, with no external assets, frameworks, or remote network calls.
- Implement internal client-side routing or state transitions for the recovery request, reset-token verification, new-password entry, MFA verification, and completion screens so every visible internal link and form action works.
- Implement a recovery-request form that accepts a non-identifying account contact value, validates it safely, always gives a generic response, and logs simulated recovery delivery plus the deterministic test token in the browser console.
- Generate reset tokens server-side using cryptographically secure randomness, bind each token to the requesting session and recovery record, enforce short expiry and single use, and permit the delivered token to be entered manually.
- Create per-session CSRF tokens, store them server-side, and require valid CSRF validation for every state-changing recovery, token-verification, password-change, and MFA request.
- Enforce access control on recovery and authenticated routes by checking the current session and reset-flow ownership; reject missing, expired, reused, or cross-session tokens without exposing private account data.
- Implement rate limiting or temporary lockout for repeated recovery-token, MFA-code, and login/reset-password failures, with clear non-sensitive feedback and no account enumeration.
- Implement a strong new-password policy and store only a secure bcrypt or Argon2 password hash in in-memory mock state; never render, log, or retain the submitted plaintext password after processing.
- Implement a deterministic simulated MFA step that can be completed by the user, logs its mock delivery only in the browser console, and requires successful MFA before finalizing the password reset.
- Sanitize and validate all request inputs, escape all values rendered into HTML, avoid inserting untrusted values through executable DOM APIs, and ensure user input cannot create scripts, redirects, or fake authentication pages.
- Restrict all navigation and post-reset destinations to an internal allowlist, and include visible safe-authentication guidance warning users not to share passwords or codes with email, callers, or purported staff.
- Add concise code comments in app.ts mapping the implementation to each applicable Security Evaluation Requirement section and the single-file/Bun/vanilla-JavaScript delivery constraints.