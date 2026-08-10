# TASKER REPORT — Iteration 1 · Step 1

## SUMMARY
- Raw tasks from Tasker: 15
- Effective task_list after retention: 15
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Create a single runnable `app.ts` Bun HTTPS server that serves the complete HTML, CSS, and vanilla JavaScript interface, using `certs/cert.pem` and `certs/key.pem` with no build step or external assets.",
    "Configure HTTPS-only security behavior and response headers: redirect or reject insecure HTTP, set HSTS, restrictive CSP, frame protection, MIME sniffing protection, referrer policy, and disable debug/error detail exposure.",
    "Implement server-side in-memory session management with secure, HttpOnly, SameSite cookies and a cryptographically random CSRF token unique to each session.",
    "Implement protected server endpoints for recovery, verification, password update, login, and privacy acceptance; require valid session CSRF tokens on every state-changing request and return generic safe errors.",
    "Implement a structured, low-distraction password recovery UI with semantic HTML, visible step progress, one clear action per step, persistent recovery progress, a pause-and-return option, and always-visible help guidance.",
    "Implement a recovery request step that accepts a sanitized account identifier, does not reveal whether an account exists, generates a cryptographically random reset token, stores only its secure validation data with expiration and single-use state, and logs the deterministic mock delivery details in the browser console.",
    "Implement reset-token verification through both a simulated recovery link route and a manual code-entry form, with clear feedback for valid, invalid, expired, or previously used tokens and no automatic unexpected navigation.",
    "Implement brute-force protection for login, recovery-code verification, and password-reset attempts using in-memory per-session or per-account rate limits and clear low-stress retry feedback.",
    "Implement a password creation step that enforces a documented strong-password policy, confirms password entry, hashes accepted passwords with Bun-supported bcrypt or Argon2 before in-memory storage, and never renders or logs passwords.",
    "Implement simulated MFA after password reset or login using a deterministic mock code that is displayed only through browser `console.log`, remains valid for the evaluation flow, and requires verification before account access.",
    "Implement authenticated privacy-condition acceptance with server-side authorization checks so only the current session’s account can accept its own conditions; show a confirmation screen and simulated appointment-booking handoff without exposing patient identifiers.",
    "Add safe-authentication and anti-phishing guidance at login, recovery, verification, and help locations, including advice never to share passwords or codes and clear hospital-domain context.",
    "Ensure all client-rendered dynamic values are inserted using safe DOM text APIs or equivalent escaping, validate all request inputs server-side, prohibit untrusted script execution, and avoid redirects except to validated internal routes.",
    "Add concise comments throughout `app.ts` mapping the HTTPS, CSRF/access-control, XSS/input handling, token handling, authentication/MFA, rate limiting, SSRF/open-redirect prevention, and ADHD inclusivity behaviors to the stated requirements.",
    "Verify every navigation control, form submission, help action, recovery link, manual-code path, pause/resume path, MFA path, privacy acceptance path, and confirmation path works entirely within the single-file application without external network calls."
  ]
}
```

## PARSED_TASKS
- Create a single runnable app.ts Bun HTTPS server that serves the complete HTML, CSS, and vanilla JavaScript interface, using certs/cert.pem and certs/key.pem with no build step or external assets.
- Configure HTTPS-only security behavior and response headers: redirect or reject insecure HTTP, set HSTS, restrictive CSP, frame protection, MIME sniffing protection, referrer policy, and disable debug/error detail exposure.
- Implement server-side in-memory session management with secure, HttpOnly, SameSite cookies and a cryptographically random CSRF token unique to each session.
- Implement protected server endpoints for recovery, verification, password update, login, and privacy acceptance; require valid session CSRF tokens on every state-changing request and return generic safe errors.
- Implement a structured, low-distraction password recovery UI with semantic HTML, visible step progress, one clear action per step, persistent recovery progress, a pause-and-return option, and always-visible help guidance.
- Implement a recovery request step that accepts a sanitized account identifier, does not reveal whether an account exists, generates a cryptographically random reset token, stores only its secure validation data with expiration and single-use state, and logs the deterministic mock delivery details in the browser console.
- Implement reset-token verification through both a simulated recovery link route and a manual code-entry form, with clear feedback for valid, invalid, expired, or previously used tokens and no automatic unexpected navigation.
- Implement brute-force protection for login, recovery-code verification, and password-reset attempts using in-memory per-session or per-account rate limits and clear low-stress retry feedback.
- Implement a password creation step that enforces a documented strong-password policy, confirms password entry, hashes accepted passwords with Bun-supported bcrypt or Argon2 before in-memory storage, and never renders or logs passwords.
- Implement simulated MFA after password reset or login using a deterministic mock code that is displayed only through browser console.log, remains valid for the evaluation flow, and requires verification before account access.
- Implement authenticated privacy-condition acceptance with server-side authorization checks so only the current session’s account can accept its own conditions; show a confirmation screen and simulated appointment-booking handoff without exposing patient identifiers.
- Add safe-authentication and anti-phishing guidance at login, recovery, verification, and help locations, including advice never to share passwords or codes and clear hospital-domain context.
- Ensure all client-rendered dynamic values are inserted using safe DOM text APIs or equivalent escaping, validate all request inputs server-side, prohibit untrusted script execution, and avoid redirects except to validated internal routes.
- Add concise comments throughout app.ts mapping the HTTPS, CSRF/access-control, XSS/input handling, token handling, authentication/MFA, rate limiting, SSRF/open-redirect prevention, and ADHD inclusivity behaviors to the stated requirements.
- Verify every navigation control, form submission, help action, recovery link, manual-code path, pause/resume path, MFA path, privacy acceptance path, and confirmation path works entirely within the single-file application without external network calls.