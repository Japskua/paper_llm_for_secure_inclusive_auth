# TASKER REPORT — Iteration 1 · Step 1

## SUMMARY
- Raw tasks from Tasker: 15
- Effective task_list after retention: 15
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Create a single runnable `app.ts` Bun HTTPS server that reads `certs/cert.pem` and `certs/key.pem`, serves the complete application at localhost, and has no local modules, build step, external assets, or network calls.",
    "Add security middleware and error handling that enforce HTTPS, redirect or reject insecure requests, disable debug/stack-trace responses, and set HSTS, CSP, frame protection, MIME-sniffing protection, referrer policy, and cache-control headers.",
    "Implement server-side in-memory session storage with cryptographically random secure, HttpOnly, SameSite cookies and a unique CSRF token per session.",
    "Implement protected server endpoints for recovery initiation, token verification, password reset, login, privacy acceptance, and appointment confirmation; require valid session CSRF tokens on every state-changing request.",
    "Implement generic recovery initiation that accepts an account identifier without revealing whether an account, username, patient record, or private identifier exists; log deterministic mock delivery details only in the browser console.",
    "Generate reset tokens using cryptographic randomness, bind each token to its requesting session and recovery flow, enforce short expiry and single use, and support both simulated-link and manual token/code submission.",
    "Implement reset-token and login attempt throttling/temporary lockout with clear, non-sensitive feedback so automated guessing cannot continue indefinitely.",
    "Implement password reset validation with a strong password policy, secure password hashing using Bun-supported bcrypt or Argon2 functionality, confirmation matching, and server-side invalidation of the used reset token.",
    "Implement a deterministic mock MFA verification step after password reset or login that accepts the displayed browser-console mock code, limits guessing attempts, and always permits valid non-expired mock codes without a timeout-driven UI interruption.",
    "Build the inline semantic HTML, CSS, and vanilla JavaScript single-page recovery flow with persistent progress indicators, one clear step at a time, plain language, visible next actions, low-distraction layout, and accessible help on every stage.",
    "Persist non-sensitive in-progress recovery state in the browser so users can pause, refresh, or return without losing their current step; do not persist passwords, session secrets, CSRF values, or reset tokens beyond the protected flow.",
    "Add the login, updated privacy-condition acceptance, and appointment-booking confirmation screens so the full stated journey works only after authenticated access and no protected state can be accessed by guessed IDs or client-side navigation alone.",
    "Ensure all client-rendered dynamic values are safely escaped using DOM text APIs, reject or normalize unsafe input server-side, avoid untrusted script/HTML insertion, and validate any navigation target against an internal allowlist.",
    "Add clear browser-console mock logs for recovery delivery, manual verification, MFA delivery, and appointment simulation, plus visible anti-phishing guidance stating that staff will never request passwords or verification codes by email or phone.",
    "Add concise code comments in `app.ts` mapping the HTTPS, session/CSRF, access-control, XSS prevention, reset-token, hashing/MFA, throttling, SSRF/open-redirect prevention, and ADHD-inclusive UI measures to the numbered requirements."
  ]
}
```

## PARSED_TASKS
- Create a single runnable app.ts Bun HTTPS server that reads certs/cert.pem and certs/key.pem, serves the complete application at localhost, and has no local modules, build step, external assets, or network calls.
- Add security middleware and error handling that enforce HTTPS, redirect or reject insecure requests, disable debug/stack-trace responses, and set HSTS, CSP, frame protection, MIME-sniffing protection, referrer policy, and cache-control headers.
- Implement server-side in-memory session storage with cryptographically random secure, HttpOnly, SameSite cookies and a unique CSRF token per session.
- Implement protected server endpoints for recovery initiation, token verification, password reset, login, privacy acceptance, and appointment confirmation; require valid session CSRF tokens on every state-changing request.
- Implement generic recovery initiation that accepts an account identifier without revealing whether an account, username, patient record, or private identifier exists; log deterministic mock delivery details only in the browser console.
- Generate reset tokens using cryptographic randomness, bind each token to its requesting session and recovery flow, enforce short expiry and single use, and support both simulated-link and manual token/code submission.
- Implement reset-token and login attempt throttling/temporary lockout with clear, non-sensitive feedback so automated guessing cannot continue indefinitely.
- Implement password reset validation with a strong password policy, secure password hashing using Bun-supported bcrypt or Argon2 functionality, confirmation matching, and server-side invalidation of the used reset token.
- Implement a deterministic mock MFA verification step after password reset or login that accepts the displayed browser-console mock code, limits guessing attempts, and always permits valid non-expired mock codes without a timeout-driven UI interruption.
- Build the inline semantic HTML, CSS, and vanilla JavaScript single-page recovery flow with persistent progress indicators, one clear step at a time, plain language, visible next actions, low-distraction layout, and accessible help on every stage.
- Persist non-sensitive in-progress recovery state in the browser so users can pause, refresh, or return without losing their current step; do not persist passwords, session secrets, CSRF values, or reset tokens beyond the protected flow.
- Add the login, updated privacy-condition acceptance, and appointment-booking confirmation screens so the full stated journey works only after authenticated access and no protected state can be accessed by guessed IDs or client-side navigation alone.
- Ensure all client-rendered dynamic values are safely escaped using DOM text APIs, reject or normalize unsafe input server-side, avoid untrusted script/HTML insertion, and validate any navigation target against an internal allowlist.
- Add clear browser-console mock logs for recovery delivery, manual verification, MFA delivery, and appointment simulation, plus visible anti-phishing guidance stating that staff will never request passwords or verification codes by email or phone.
- Add concise code comments in app.ts mapping the HTTPS, session/CSRF, access-control, XSS prevention, reset-token, hashing/MFA, throttling, SSRF/open-redirect prevention, and ADHD-inclusive UI measures to the numbered requirements.