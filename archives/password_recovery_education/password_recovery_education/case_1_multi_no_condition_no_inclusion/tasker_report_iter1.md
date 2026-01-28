# TASKER REPORT — Iteration 1 · Step 1

## SUMMARY
- Raw tasks from Tasker: 25
- Effective task_list after retention: 25
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Start an HTTPS Bun server using certs/cert.pem and certs/key.pem on a chosen port, plus an HTTP server that redirects to HTTPS (301).",
    "Add strict security headers (HSTS, CSP with per-response nonce, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy) to all HTML/API responses.",
    "Implement in-memory stores for users, sessions, CSRF tokens, login attempts, reset tokens (single-use with expiry), and MFA challenges.",
    "Issue a Secure, HttpOnly, SameSite=Strict session cookie on first visit and persist a per-session CSRF token.",
    "Serve a single HTML page (GET /) with semantic structure, minimal CSS, and a nonce’d inline script; inject CSRF token and script nonce safely.",
    "Create client-side hash-based router to show views: login, forgot-password, enter-code, reset-password, MFA, and confirmation without reloading.",
    "Ensure client JS reads CSRF token from DOM/meta and includes it in all POST fetch requests to same-origin API endpoints.",
    "Implement POST /api/request-reset to accept an identifier and CSRF, enforce rate limiting, generate a random single-use short-lived token, and return a generic success plus the token in JSON.",
    "In the client, build the Forgot Password form that submits to /api/request-reset, logs the simulated delivery (email/SMS) and the token to console, and provides a manual code entry link.",
    "Implement POST /api/verify-reset to accept token and CSRF, validate token existence/expiry, mark it as verified, and return success.",
    "Create the Enter Code view to submit the token manually to /api/verify-reset and, on success, navigate to Reset Password.",
    "Enforce a strong password policy on server (length, upper/lower/number/symbol) and return specific validation messages on failure.",
    "Hash new passwords using Bun.password.hash (argon2id or bcrypt) and store only the hash in memory.",
    "Implement POST /api/set-password to accept token, CSRF, and new password; verify token is valid/verified, enforce policy, hash, consume token, and return success.",
    "Build the Reset Password view with client-side checks (mirroring server policy) and submission to /api/set-password; on success, route to login.",
    "Implement POST /api/login with CSRF, bcrypt/argon2 verification, generic error messages, and rate limiting/cooldown after repeated failures.",
    "On successful login, initiate MFA by creating a deterministic mock code server-side and returning it in JSON; do not reveal user existence differences.",
    "Create the MFA view to allow manual code entry; log the mock code to console for simulation and submit to verification API.",
    "Implement POST /api/verify-mfa to accept code and CSRF, validate against the issued MFA challenge (allow deterministic code to always work), and establish an authenticated session flag.",
    "Ensure all sensitive API endpoints (request-reset, verify-reset, set-password, login, verify-mfa, logout) validate CSRF and session presence as appropriate.",
    "Sanitize and validate all incoming fields (identifier, token, password, code) and escape any data reflected in responses; never use innerHTML for user data.",
    "Ensure generic, non-enumerating responses for login and password reset requests regardless of account existence.",
    "Block open redirects by validating/whitelisting any next/return parameters to internal routes only.",
    "Add a Logout endpoint (POST /api/logout) that clears session cookie and invalidates session state.",
    "Include clear code comments mapping each major block to the corresponding Security Requirements sections (1–5) and Additional Constraints."
  ]
}
```

## PARSED_TASKS
- Start an HTTPS Bun server using certs/cert.pem and certs/key.pem on a chosen port, plus an HTTP server that redirects to HTTPS (301).
- Add strict security headers (HSTS, CSP with per-response nonce, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy) to all HTML/API responses.
- Implement in-memory stores for users, sessions, CSRF tokens, login attempts, reset tokens (single-use with expiry), and MFA challenges.
- Issue a Secure, HttpOnly, SameSite=Strict session cookie on first visit and persist a per-session CSRF token.
- Serve a single HTML page (GET /) with semantic structure, minimal CSS, and a nonce’d inline script; inject CSRF token and script nonce safely.
- Create client-side hash-based router to show views: login, forgot-password, enter-code, reset-password, MFA, and confirmation without reloading.
- Ensure client JS reads CSRF token from DOM/meta and includes it in all POST fetch requests to same-origin API endpoints.
- Implement POST /api/request-reset to accept an identifier and CSRF, enforce rate limiting, generate a random single-use short-lived token, and return a generic success plus the token in JSON.
- In the client, build the Forgot Password form that submits to /api/request-reset, logs the simulated delivery (email/SMS) and the token to console, and provides a manual code entry link.
- Implement POST /api/verify-reset to accept token and CSRF, validate token existence/expiry, mark it as verified, and return success.
- Create the Enter Code view to submit the token manually to /api/verify-reset and, on success, navigate to Reset Password.
- Enforce a strong password policy on server (length, upper/lower/number/symbol) and return specific validation messages on failure.
- Hash new passwords using Bun.password.hash (argon2id or bcrypt) and store only the hash in memory.
- Implement POST /api/set-password to accept token, CSRF, and new password; verify token is valid/verified, enforce policy, hash, consume token, and return success.
- Build the Reset Password view with client-side checks (mirroring server policy) and submission to /api/set-password; on success, route to login.
- Implement POST /api/login with CSRF, bcrypt/argon2 verification, generic error messages, and rate limiting/cooldown after repeated failures.
- On successful login, initiate MFA by creating a deterministic mock code server-side and returning it in JSON; do not reveal user existence differences.
- Create the MFA view to allow manual code entry; log the mock code to console for simulation and submit to verification API.
- Implement POST /api/verify-mfa to accept code and CSRF, validate against the issued MFA challenge (allow deterministic code to always work), and establish an authenticated session flag.
- Ensure all sensitive API endpoints (request-reset, verify-reset, set-password, login, verify-mfa, logout) validate CSRF and session presence as appropriate.
- Sanitize and validate all incoming fields (identifier, token, password, code) and escape any data reflected in responses; never use innerHTML for user data.
- Ensure generic, non-enumerating responses for login and password reset requests regardless of account existence.
- Block open redirects by validating/whitelisting any next/return parameters to internal routes only.
- Add a Logout endpoint (POST /api/logout) that clears session cookie and invalidates session state.
- Include clear code comments mapping each major block to the corresponding Security Requirements sections (1–5) and Additional Constraints.