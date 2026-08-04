# TASKER REPORT — Iteration 1 · Step 1

## SUMMARY
- Raw tasks from Tasker: 18
- Effective task_list after retention: 18
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Create a single runnable `app.ts` that starts a Bun HTTPS server using `certs/cert.pem` and `certs/key.pem`, serves the complete HTML/CSS/vanilla-JavaScript SPA, and handles no local modules or build steps.",
    "Configure HTTPS-only security behavior: redirect or reject insecure requests, add HSTS, CSP, frame protection, MIME sniffing protection, referrer policy, and restrictive cache-control headers without exposing debug details.",
    "Implement an in-memory session store with cryptographically random session identifiers, Secure/HttpOnly/SameSite cookies, session-bound CSRF tokens, and server-side expiry handling.",
    "Implement SPA routing for login, recovery request, reset-token verification, password creation, privacy acceptance, confirmation, pause/resume, and help views so every internal navigation path is functional.",
    "Create a calm, accessible step-by-step recovery interface with semantic HTML, visible current-step progress, concise next-action guidance, consistent controls, and no time-pressure messaging.",
    "Persist non-sensitive recovery progress in the active server-side session so a user can pause, return, and continue without losing the current recovery step.",
    "Provide a clearly accessible help panel on every recovery view that gives safe guidance, explains that passwords and codes must never be shared, and does not disclose account information.",
    "Implement a generic password-recovery request endpoint that accepts an account identifier without revealing whether an account exists, validates CSRF, and throttles repeated requests.",
    "Generate recovery tokens with cryptographically secure randomness, bind each token to its requesting session and recovery record, enforce short expiration and single use, and never place private account data in links or responses.",
    "Return the deterministic mock recovery token only to the current browser recovery flow for academic testing and log simulated delivery plus the token with `console.log` in the browser.",
    "Allow recovery token verification through both the simulated verification link route and a manual code-entry form, with equivalent CSRF validation, expiry checks, single-use enforcement, and clear non-sensitive feedback.",
    "Implement brute-force protection for login and recovery-token verification using per-session and/or per-identifier attempt limits with a user-friendly wait message rather than account disclosure.",
    "Implement password creation with a clearly displayed strong-password policy, confirmation matching, server-side validation, and secure hashing using Bun-supported bcrypt or Argon2 before storing the replacement credential.",
    "Implement login with server-side credential verification against the stored password hash, generic failure messages, CSRF validation, and throttling/temporary lockout after repeated failed attempts.",
    "Require a completed recovery and authenticated session before allowing privacy-condition acceptance or appointment-related confirmation, and enforce server-side authorization for every sensitive route.",
    "Implement privacy-condition acceptance as a CSRF-protected state change associated only with the authenticated session, followed by a clear confirmation that authorities can proceed with booking.",
    "Sanitize and validate all request inputs, escape all dynamic content rendered into HTML, avoid dynamic script injection and unsafe URL handling, and restrict navigation targets to the app's known internal routes.",
    "Add concise comments in `app.ts` mapping the HTTPS, session/CSRF, input handling, token, authentication, authorization, phishing-safety, and accessibility implementation points to the corresponding stated requirements."
  ]
}
```

## PARSED_TASKS
- Create a single runnable app.ts that starts a Bun HTTPS server using certs/cert.pem and certs/key.pem, serves the complete HTML/CSS/vanilla-JavaScript SPA, and handles no local modules or build steps.
- Configure HTTPS-only security behavior: redirect or reject insecure requests, add HSTS, CSP, frame protection, MIME sniffing protection, referrer policy, and restrictive cache-control headers without exposing debug details.
- Implement an in-memory session store with cryptographically random session identifiers, Secure/HttpOnly/SameSite cookies, session-bound CSRF tokens, and server-side expiry handling.
- Implement SPA routing for login, recovery request, reset-token verification, password creation, privacy acceptance, confirmation, pause/resume, and help views so every internal navigation path is functional.
- Create a calm, accessible step-by-step recovery interface with semantic HTML, visible current-step progress, concise next-action guidance, consistent controls, and no time-pressure messaging.
- Persist non-sensitive recovery progress in the active server-side session so a user can pause, return, and continue without losing the current recovery step.
- Provide a clearly accessible help panel on every recovery view that gives safe guidance, explains that passwords and codes must never be shared, and does not disclose account information.
- Implement a generic password-recovery request endpoint that accepts an account identifier without revealing whether an account exists, validates CSRF, and throttles repeated requests.
- Generate recovery tokens with cryptographically secure randomness, bind each token to its requesting session and recovery record, enforce short expiration and single use, and never place private account data in links or responses.
- Return the deterministic mock recovery token only to the current browser recovery flow for academic testing and log simulated delivery plus the token with console.log in the browser.
- Allow recovery token verification through both the simulated verification link route and a manual code-entry form, with equivalent CSRF validation, expiry checks, single-use enforcement, and clear non-sensitive feedback.
- Implement brute-force protection for login and recovery-token verification using per-session and/or per-identifier attempt limits with a user-friendly wait message rather than account disclosure.
- Implement password creation with a clearly displayed strong-password policy, confirmation matching, server-side validation, and secure hashing using Bun-supported bcrypt or Argon2 before storing the replacement credential.
- Implement login with server-side credential verification against the stored password hash, generic failure messages, CSRF validation, and throttling/temporary lockout after repeated failed attempts.
- Require a completed recovery and authenticated session before allowing privacy-condition acceptance or appointment-related confirmation, and enforce server-side authorization for every sensitive route.
- Implement privacy-condition acceptance as a CSRF-protected state change associated only with the authenticated session, followed by a clear confirmation that authorities can proceed with booking.
- Sanitize and validate all request inputs, escape all dynamic content rendered into HTML, avoid dynamic script injection and unsafe URL handling, and restrict navigation targets to the app's known internal routes.
- Add concise comments in app.ts mapping the HTTPS, session/CSRF, input handling, token, authentication, authorization, phishing-safety, and accessibility implementation points to the corresponding stated requirements.