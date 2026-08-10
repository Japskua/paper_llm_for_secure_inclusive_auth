# TASKER REPORT — Iteration 1 · Step 1

## SUMMARY
- Raw tasks from Tasker: 12
- Effective task_list after retention: 12
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Create a single runnable `app.ts` Bun HTTPS server that loads `certs/cert.pem` and `certs/key.pem`, serves the complete inline HTML/CSS/vanilla-JS SPA, redirects HTTP to HTTPS, and adds HSTS, CSP, anti-framing, MIME-sniffing, referrer, and cache-control headers.",
    "Implement server-side in-memory session handling with cryptographically random Secure/HttpOnly/SameSite cookies and unique per-session CSRF tokens; require and validate CSRF tokens for every state-changing endpoint.",
    "Implement a minimal recovery state model and server endpoints that use only generic account-existence responses, avoid exposing patient/user identifiers, and enforce authorization and ownership checks on every sensitive action.",
    "Implement password-reset request handling that creates cryptographically random, short-lived, single-use reset tokens, returns no token in page content, and returns the deterministic mock token only through a browser-visible API result that client JavaScript logs with `console.log` for testing.",
    "Implement reset-token verification usable both from the simulated recovery link and a manual code-entry form; reject expired, used, malformed, or non-owned tokens with clear generic feedback and no sensitive disclosure.",
    "Implement MFA verification with a deterministic mock code that remains valid, browser `console.log` delivery, CSRF protection, and rate limiting; require successful MFA plus a valid reset token before allowing password changes.",
    "Implement strong-password validation and server-side password hashing using Bun-supported bcrypt or Argon2 before storage; never store, render, log, or return plaintext passwords.",
    "Implement login and verification attempt throttling/temporary lockout after repeated failures, with generic messages and no account enumeration; log simulated security events only without credentials or private identifiers.",
    "Build the accessible, low-distraction recovery SPA with semantic HTML, visible numbered progress, one clearly labeled step at a time, persistent in-browser progress, pause/resume messaging, no countdowns or session timeouts, clear next-step feedback, and a consistently available help/safe-authentication panel.",
    "Ensure all client rendering escapes dynamic text and uses safe DOM APIs, validates inputs before submission, contains no untrusted inline script execution, makes no external network calls, and prevents arbitrary redirects or outgoing URLs.",
    "Add concise comments in `app.ts` mapping the HTTPS, CSRF/access control, XSS/output escaping, reset-token, authentication/MFA, rate-limit, SSRF/open-redirect, and ADHD inclusivity implementations to the stated requirements.",
    "Verify every SPA navigation, recovery-link route/query flow, manual-code flow, MFA flow, password-change confirmation, help control, and return/resume path works entirely through `app.ts` without broken links or external files."
  ]
}
```

## PARSED_TASKS
- Create a single runnable app.ts Bun HTTPS server that loads certs/cert.pem and certs/key.pem, serves the complete inline HTML/CSS/vanilla-JS SPA, redirects HTTP to HTTPS, and adds HSTS, CSP, anti-framing, MIME-sniffing, referrer, and cache-control headers.
- Implement server-side in-memory session handling with cryptographically random Secure/HttpOnly/SameSite cookies and unique per-session CSRF tokens; require and validate CSRF tokens for every state-changing endpoint.
- Implement a minimal recovery state model and server endpoints that use only generic account-existence responses, avoid exposing patient/user identifiers, and enforce authorization and ownership checks on every sensitive action.
- Implement password-reset request handling that creates cryptographically random, short-lived, single-use reset tokens, returns no token in page content, and returns the deterministic mock token only through a browser-visible API result that client JavaScript logs with console.log for testing.
- Implement reset-token verification usable both from the simulated recovery link and a manual code-entry form; reject expired, used, malformed, or non-owned tokens with clear generic feedback and no sensitive disclosure.
- Implement MFA verification with a deterministic mock code that remains valid, browser console.log delivery, CSRF protection, and rate limiting; require successful MFA plus a valid reset token before allowing password changes.
- Implement strong-password validation and server-side password hashing using Bun-supported bcrypt or Argon2 before storage; never store, render, log, or return plaintext passwords.
- Implement login and verification attempt throttling/temporary lockout after repeated failures, with generic messages and no account enumeration; log simulated security events only without credentials or private identifiers.
- Build the accessible, low-distraction recovery SPA with semantic HTML, visible numbered progress, one clearly labeled step at a time, persistent in-browser progress, pause/resume messaging, no countdowns or session timeouts, clear next-step feedback, and a consistently available help/safe-authentication panel.
- Ensure all client rendering escapes dynamic text and uses safe DOM APIs, validates inputs before submission, contains no untrusted inline script execution, makes no external network calls, and prevents arbitrary redirects or outgoing URLs.
- Add concise comments in app.ts mapping the HTTPS, CSRF/access control, XSS/output escaping, reset-token, authentication/MFA, rate-limit, SSRF/open-redirect, and ADHD inclusivity implementations to the stated requirements.
- Verify every SPA navigation, recovery-link route/query flow, manual-code flow, MFA flow, password-change confirmation, help control, and return/resume path works entirely through app.ts without broken links or external files.