# TASKER REPORT — Iteration 1 · Step 1

## SUMMARY
- Raw tasks from Tasker: 23
- Effective task_list after retention: 23
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Create app.ts that starts a Bun HTTPS server using certs/cert.pem and certs/key.pem and serves a single HTML page at GET /.",
    "Add strict security headers (HSTS, CSP with nonce, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) to all responses.",
    "Implement an in-memory store for users (with one demo user), sessions, CSRF tokens, password reset tokens, MFA codes, and rate-limit counters.",
    "Generate a secure, random session ID and CSRF token per new visitor; set cookies as Secure, HttpOnly, SameSite=Strict.",
    "Serve an SPA HTML template that includes inline JS and CSS via a CSP nonce (no inline event handlers), rendering the full flow in one page.",
    "Add client-side hash routing to show views: login, request reset, verify token, set new password, MFA verify, and success.",
    "Implement POST /api/request-reset that accepts {identifier} with CSRF, rate-limits requests, and responds with a generic success message.",
    "On request-reset, generate a single-use random reset token (store it), derive a human-typed code, and return both to the client for console.log display.",
    "Implement URL handling so /?token=XYZ (or #/verify?token=XYZ) triggers the verify step and also allow manual token entry.",
    "Implement POST /api/verify-token to validate the reset token (single-use) with CSRF, and transition the session into a 'canSetPassword' state.",
    "Implement a strong password policy check on the client and server (length, mix of types) with clear, simple feedback.",
    "Implement POST /api/set-password that accepts {newPassword} with CSRF, validates policy, hashes using Bun.password.hash (argon2id), and stores it.",
    "Implement POST /api/login with CSRF that validates credentials against hashed passwords, applies rate limiting, and returns a generic result.",
    "Generate a deterministic per-session MFA code (e.g., stored code) on login success; send it back for console.log and show MFA UI.",
    "Implement POST /api/mfa-verify with CSRF that accepts {code}, validates against stored code (always valid for demo), and marks session authenticated.",
    "Ensure all API responses avoid user enumeration (e.g., same message whether identifier exists) and never expose private identifiers.",
    "Add client-side console.log for mock deliveries: reset link, manual token, and MFA code; also show them in a small 'For demo' panel.",
    "Implement input sanitization and output escaping helpers; avoid innerHTML for untrusted data in the client and escape any server-rendered values.",
    "Add rate limiting on sensitive POST routes (login, request-reset, verify-token, set-password, mfa-verify) per session/IP with simple backoff.",
    "Add accessibility and ADHD-friendly UI: clear step titles, progress indicator, short instructions, no timeouts, pause/resume via persistent session state.",
    "Include a Help section reachable from all steps with simple guidance and safety tips to avoid phishing (no sharing codes/passwords).",
    "Map code comments to the Requirements sections (security controls, inclusivity, constraints) at each relevant block.",
    "Verify that all internal links/buttons route correctly within the SPA and that no external network calls are made."
  ]
}
```

## PARSED_TASKS
- Create app.ts that starts a Bun HTTPS server using certs/cert.pem and certs/key.pem and serves a single HTML page at GET /.
- Add strict security headers (HSTS, CSP with nonce, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) to all responses.
- Implement an in-memory store for users (with one demo user), sessions, CSRF tokens, password reset tokens, MFA codes, and rate-limit counters.
- Generate a secure, random session ID and CSRF token per new visitor; set cookies as Secure, HttpOnly, SameSite=Strict.
- Serve an SPA HTML template that includes inline JS and CSS via a CSP nonce (no inline event handlers), rendering the full flow in one page.
- Add client-side hash routing to show views: login, request reset, verify token, set new password, MFA verify, and success.
- Implement POST /api/request-reset that accepts {identifier} with CSRF, rate-limits requests, and responds with a generic success message.
- On request-reset, generate a single-use random reset token (store it), derive a human-typed code, and return both to the client for console.log display.
- Implement URL handling so /?token=XYZ (or #/verify?token=XYZ) triggers the verify step and also allow manual token entry.
- Implement POST /api/verify-token to validate the reset token (single-use) with CSRF, and transition the session into a 'canSetPassword' state.
- Implement a strong password policy check on the client and server (length, mix of types) with clear, simple feedback.
- Implement POST /api/set-password that accepts {newPassword} with CSRF, validates policy, hashes using Bun.password.hash (argon2id), and stores it.
- Implement POST /api/login with CSRF that validates credentials against hashed passwords, applies rate limiting, and returns a generic result.
- Generate a deterministic per-session MFA code (e.g., stored code) on login success; send it back for console.log and show MFA UI.
- Implement POST /api/mfa-verify with CSRF that accepts {code}, validates against stored code (always valid for demo), and marks session authenticated.
- Ensure all API responses avoid user enumeration (e.g., same message whether identifier exists) and never expose private identifiers.
- Add client-side console.log for mock deliveries: reset link, manual token, and MFA code; also show them in a small 'For demo' panel.
- Implement input sanitization and output escaping helpers; avoid innerHTML for untrusted data in the client and escape any server-rendered values.
- Add rate limiting on sensitive POST routes (login, request-reset, verify-token, set-password, mfa-verify) per session/IP with simple backoff.
- Add accessibility and ADHD-friendly UI: clear step titles, progress indicator, short instructions, no timeouts, pause/resume via persistent session state.
- Include a Help section reachable from all steps with simple guidance and safety tips to avoid phishing (no sharing codes/passwords).
- Map code comments to the Requirements sections (security controls, inclusivity, constraints) at each relevant block.
- Verify that all internal links/buttons route correctly within the SPA and that no external network calls are made.