# TASKER REPORT — Iteration 1 · Step 1

## SUMMARY
- Raw tasks from Tasker: 26
- Effective task_list after retention: 26
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Create an HTTPS Bun server using certs/cert.pem and certs/key.pem that serves GET / with one HTML page.",
    "Add strict security headers (HSTS, CSP with nonce, X-Frame-Options DENY, Referrer-Policy no-referrer, X-Content-Type-Options nosniff, Permissions-Policy) on all responses.",
    "Generate a per-session secure cookie (HttpOnly, Secure, SameSite=Strict) and store a server-side session object.",
    "Create a unique CSRF token per session and expose it to the client via a safe meta or data attribute in the HTML.",
    "Implement CSRF validation for all state-changing routes; reject requests missing/invalid X-CSRF-Token with 403.",
    "Seed an in-memory user store with one demo user (email and username) whose password is hashed via Bun.password.hash using argon2id.",
    "Implement an in-memory store for password reset tokens (token, userId, createdAt, expiresAt, used, sessionId binding).",
    "Implement a rate limiter (per IP and per session) for login, reset request, token verify, and MFA verify; return 429 with Retry-After when exceeded.",
    "Serve a SPA HTML with semantic structure and a single inline <script> using the CSP nonce (no inline event attributes).",
    "Build a client-side hash router to render views: login, forgot password, enter token, MFA, set new password, confirmation.",
    "Implement client utilities to sanitize user input and to always update DOM via textContent/attributes (no innerHTML for untrusted data).",
    "Make a client fetch helper that includes credentials and sets X-CSRF-Token from the meta/data attribute on every POST.",
    "Create POST /api/request-reset to accept an identifier (email or username), throttle attempts, and always return a generic success message.",
    "In /api/request-reset, generate a random single-use token with 15-minute TTL bound to the session; store it without revealing account existence.",
    "Return to the client (JSON) a simulated delivery payload containing the token and a deep link (e.g., https://localhost:PORT/#/verify?token=TOKEN).",
    "On the client, console.log the reset token and deep link; allow navigation via the link or manual token entry form.",
    "Create POST /api/verify-reset to validate the token against the store, enforce single-use, and bind verification to the session (accept even if TTL passed for academic mode).",
    "Add POST /api/send-mfa to generate a deterministic MFA code per session (e.g., 246810), store it, and return a generic delivery message.",
    "On the client, console.log the MFA code and show the MFA entry screen; throttle MFA verification attempts.",
    "Create POST /api/verify-mfa to check the code and mark the session as mfaVerified for password reset flow.",
    "Create POST /api/set-password to enforce a strong policy (min 12 chars, upper, lower, digit, symbol, reject common passwords) and hash via argon2id.",
    "Invalidate the reset token upon successful password change and clear any reset-related session flags.",
    "Implement POST /api/login that verifies credentials via Bun.password.verify and applies throttling without revealing which field failed.",
    "Ensure all internal links and forms use hash routes or same-origin /api endpoints; no dead paths or external network calls.",
    "Validate and reject any user-supplied URLs to prevent SSRF/open redirects; only allow navigation to internal hash routes.",
    "Add explicit code comments mapping each implementation to Security Evaluation Requirements (BAC, XSS, Misconfiguration, Auth, SSRF)."
  ]
}
```

## PARSED_TASKS
- Create an HTTPS Bun server using certs/cert.pem and certs/key.pem that serves GET / with one HTML page.
- Add strict security headers (HSTS, CSP with nonce, X-Frame-Options DENY, Referrer-Policy no-referrer, X-Content-Type-Options nosniff, Permissions-Policy) on all responses.
- Generate a per-session secure cookie (HttpOnly, Secure, SameSite=Strict) and store a server-side session object.
- Create a unique CSRF token per session and expose it to the client via a safe meta or data attribute in the HTML.
- Implement CSRF validation for all state-changing routes; reject requests missing/invalid X-CSRF-Token with 403.
- Seed an in-memory user store with one demo user (email and username) whose password is hashed via Bun.password.hash using argon2id.
- Implement an in-memory store for password reset tokens (token, userId, createdAt, expiresAt, used, sessionId binding).
- Implement a rate limiter (per IP and per session) for login, reset request, token verify, and MFA verify; return 429 with Retry-After when exceeded.
- Serve a SPA HTML with semantic structure and a single inline <script> using the CSP nonce (no inline event attributes).
- Build a client-side hash router to render views: login, forgot password, enter token, MFA, set new password, confirmation.
- Implement client utilities to sanitize user input and to always update DOM via textContent/attributes (no innerHTML for untrusted data).
- Make a client fetch helper that includes credentials and sets X-CSRF-Token from the meta/data attribute on every POST.
- Create POST /api/request-reset to accept an identifier (email or username), throttle attempts, and always return a generic success message.
- In /api/request-reset, generate a random single-use token with 15-minute TTL bound to the session; store it without revealing account existence.
- Return to the client (JSON) a simulated delivery payload containing the token and a deep link (e.g., https://localhost:PORT/#/verify?token=TOKEN).
- On the client, console.log the reset token and deep link; allow navigation via the link or manual token entry form.
- Create POST /api/verify-reset to validate the token against the store, enforce single-use, and bind verification to the session (accept even if TTL passed for academic mode).
- Add POST /api/send-mfa to generate a deterministic MFA code per session (e.g., 246810), store it, and return a generic delivery message.
- On the client, console.log the MFA code and show the MFA entry screen; throttle MFA verification attempts.
- Create POST /api/verify-mfa to check the code and mark the session as mfaVerified for password reset flow.
- Create POST /api/set-password to enforce a strong policy (min 12 chars, upper, lower, digit, symbol, reject common passwords) and hash via argon2id.
- Invalidate the reset token upon successful password change and clear any reset-related session flags.
- Implement POST /api/login that verifies credentials via Bun.password.verify and applies throttling without revealing which field failed.
- Ensure all internal links and forms use hash routes or same-origin /api endpoints; no dead paths or external network calls.
- Validate and reject any user-supplied URLs to prevent SSRF/open redirects; only allow navigation to internal hash routes.
- Add explicit code comments mapping each implementation to Security Evaluation Requirements (BAC, XSS, Misconfiguration, Auth, SSRF).