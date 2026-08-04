# TASKER REPORT — Iteration 1 · Step 1

## SUMMARY
- Raw tasks from Tasker: 19
- Effective task_list after retention: 19
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Create a single runnable `app.ts` that starts a Bun 1.3.0 HTTPS server using `certs/cert.pem` and `certs/key.pem`, serves the complete application, and requires no local modules, build tools, or external assets.",
    "Implement an HTTPS-only request boundary that rejects insecure requests and returns security headers including HSTS, a restrictive CSP, frame protection, MIME sniffing protection, referrer policy, and no-cache directives for sensitive pages.",
    "Embed the entire client as semantic HTML, minimal CSS, and vanilla browser JavaScript inside the HTML response from `app.ts`; do not use frameworks, external scripts, or remote network requests.",
    "Build a calm, accessible password-recovery interface with a persistent step indicator, one clear action per screen, visible next-step guidance, easy-to-find help, and no timeouts or automatic navigation.",
    "Persist unfinished recovery progress safely in browser storage so a user can pause, close the page, and return without losing the current non-sensitive step; provide a clear restart option.",
    "Implement the initial account-recovery request form without revealing whether an entered account identifier exists, and show safe-authentication guidance that passwords and codes must never be shared by email or with support staff.",
    "Create per-session server-side session state with a cryptographically random, Secure, HttpOnly, SameSite cookie and a unique CSRF token; require and validate that CSRF token on every state-changing request.",
    "Generate cryptographically random password-reset tokens that are bound to the requesting session/account recovery state, expire after a short server-enforced lifetime, and become invalid immediately after successful use.",
    "Simulate recovery delivery only in browser `console.log`, returning the deterministic testing value needed to continue the flow without exposing private account identifiers in the UI or server responses.",
    "Provide a verification screen that accepts either the delivered recovery link/token route or manual entry of the displayed recovery code, validates it server-side, and gives clear non-sensitive success or retry feedback.",
    "Rate-limit recovery, verification, login, and password-change attempts by session and request source, with a clear temporary-block message after repeated failures and no account-enumeration details.",
    "Implement a working simulated MFA step after reset-token verification, log its deterministic test code in the browser console, accept the code without expiration during the evaluation, and protect MFA submission with CSRF and throttling.",
    "Implement a password-change form that enforces a documented strong password policy, confirms the repeated password, rejects weak or mismatched submissions with clear feedback, and never renders or logs entered passwords.",
    "Store the simulated account password only as a bcrypt or Argon2 hash, replace that hash only after valid reset-token and MFA checks, and invalidate the used reset token and related recovery state after success.",
    "Implement a post-reset sign-in and privacy-conditions confirmation flow that requires the authenticated server-side session, protects state changes with CSRF, and never exposes protected user or patient information to unauthenticated users.",
    "Ensure every client-visible route, form action, verification link, help action, restart action, and confirmation navigation is handled within `app.ts`, with safe fallback handling for unknown paths and no open redirects.",
    "Validate all request inputs by expected type, length, and format; escape all data rendered into HTML; avoid assigning untrusted content through executable HTML/URL sinks; and reject unsafe redirect or outgoing URL values.",
    "Avoid exposing usernames, patient details, internal folders, tokens, session data, debug errors, directory listings, or stack traces in HTML, API responses, logs, and error pages.",
    "Add concise code comments in `app.ts` mapping the implementation to the relevant functional, inclusivity, and OWASP/security requirement sections."
  ]
}
```

## PARSED_TASKS
- Create a single runnable app.ts that starts a Bun 1.3.0 HTTPS server using certs/cert.pem and certs/key.pem, serves the complete application, and requires no local modules, build tools, or external assets.
- Implement an HTTPS-only request boundary that rejects insecure requests and returns security headers including HSTS, a restrictive CSP, frame protection, MIME sniffing protection, referrer policy, and no-cache directives for sensitive pages.
- Embed the entire client as semantic HTML, minimal CSS, and vanilla browser JavaScript inside the HTML response from app.ts; do not use frameworks, external scripts, or remote network requests.
- Build a calm, accessible password-recovery interface with a persistent step indicator, one clear action per screen, visible next-step guidance, easy-to-find help, and no timeouts or automatic navigation.
- Persist unfinished recovery progress safely in browser storage so a user can pause, close the page, and return without losing the current non-sensitive step; provide a clear restart option.
- Implement the initial account-recovery request form without revealing whether an entered account identifier exists, and show safe-authentication guidance that passwords and codes must never be shared by email or with support staff.
- Create per-session server-side session state with a cryptographically random, Secure, HttpOnly, SameSite cookie and a unique CSRF token; require and validate that CSRF token on every state-changing request.
- Generate cryptographically random password-reset tokens that are bound to the requesting session/account recovery state, expire after a short server-enforced lifetime, and become invalid immediately after successful use.
- Simulate recovery delivery only in browser console.log, returning the deterministic testing value needed to continue the flow without exposing private account identifiers in the UI or server responses.
- Provide a verification screen that accepts either the delivered recovery link/token route or manual entry of the displayed recovery code, validates it server-side, and gives clear non-sensitive success or retry feedback.
- Rate-limit recovery, verification, login, and password-change attempts by session and request source, with a clear temporary-block message after repeated failures and no account-enumeration details.
- Implement a working simulated MFA step after reset-token verification, log its deterministic test code in the browser console, accept the code without expiration during the evaluation, and protect MFA submission with CSRF and throttling.
- Implement a password-change form that enforces a documented strong password policy, confirms the repeated password, rejects weak or mismatched submissions with clear feedback, and never renders or logs entered passwords.
- Store the simulated account password only as a bcrypt or Argon2 hash, replace that hash only after valid reset-token and MFA checks, and invalidate the used reset token and related recovery state after success.
- Implement a post-reset sign-in and privacy-conditions confirmation flow that requires the authenticated server-side session, protects state changes with CSRF, and never exposes protected user or patient information to unauthenticated users.
- Ensure every client-visible route, form action, verification link, help action, restart action, and confirmation navigation is handled within app.ts, with safe fallback handling for unknown paths and no open redirects.
- Validate all request inputs by expected type, length, and format; escape all data rendered into HTML; avoid assigning untrusted content through executable HTML/URL sinks; and reject unsafe redirect or outgoing URL values.
- Avoid exposing usernames, patient details, internal folders, tokens, session data, debug errors, directory listings, or stack traces in HTML, API responses, logs, and error pages.
- Add concise code comments in app.ts mapping the implementation to the relevant functional, inclusivity, and OWASP/security requirement sections.