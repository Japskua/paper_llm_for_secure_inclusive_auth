# TASKER REPORT — Iteration 1 · Step 1

## SUMMARY
- Raw tasks from Tasker: 20
- Effective task_list after retention: 20
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Start an HTTPS Bun server on 3443 using certs/cert.pem and certs/key.pem and set HSTS, CSP-with-nonce, Referrer-Policy, X-Content-Type-Options, and frame protections; also start HTTP on 3000 that 301-redirects to HTTPS.",
    "Serve a single HTML page for all GET routes with a nonce-tagged inline script and minimal inline CSS; include a root SPA container and high-contrast, readable styles.",
    "Implement in-memory stores for users (include Alex), sessions, reset tokens, MFA codes, and rate limits; avoid exposing PII in responses.",
    "Create a per-session CSRF token stored server-side; set a Secure, HttpOnly, SameSite=Strict 'sid' cookie and expose CSRF via a JSON endpoint for the SPA.",
    "Build a client-side hash router (#/login, #/forgot, #/verify, #/mfa, #/set-password, #/done) and ensure navigation works without full reloads.",
    "Add inclusivity helpers: a 'Read aloud' button using SpeechSynthesis and 'Copy' buttons for codes/instructions on all relevant views.",
    "Implement POST /api/login that validates CSRF, throttles by IP+identifier, verifies password (bcrypt/Argon2 via Bun.password), and returns generic success/failure.",
    "Add MFA enrollment for Alex and POST /api/mfa/verify; generate a deterministic 6-digit code, log it to the browser console, and accept manual entry reliably.",
    "Implement POST /api/reset/start that accepts an email (sanitized), always returns a generic success, generates a random single-use token, stores it, logs the reset link/code to the browser console, and returns the token in JSON.",
    "Implement GET /api/reset/preview?token=... to validate a token and set a session reset context without revealing user existence; return JSON {ok:true}.",
    "Implement POST /api/reset/verify that accepts a token/code (from link or manual), checks single-use validity, sets a session flag to allow password setting, and returns JSON {ok:true}.",
    "Implement POST /api/password/set that enforces a strong policy (length and character classes), validates CSRF and reset context, hashes with Bun.password.hash, saves the hash, and invalidates the token.",
    "Add brute-force throttling/backoff for login and reset endpoints (e.g., 5 attempts/min per IP and per identifier) with clear generic error messages.",
    "Create input sanitization and output escaping helpers; ensure all server-rendered dynamic text uses escaping and client DOM updates use textContent.",
    "Harden CSP: script-src with a nonce and disallow inline event handlers/eval; verify the SPA works under CSP by relying only on the nonce-tagged script.",
    "Block SSRF/open redirects by ignoring external URLs in any 'next' or redirect-like parameters; only allow internal hash routes.",
    "Design concise, bullet-based UI copy with headings, spacing, and consistent naming; include a password checklist and show/hide toggle for clarity.",
    "Log all simulated deliveries (reset link, token, and MFA code) to the browser console on the client side as required, without exposing them by default in the DOM.",
    "Add a minimal post-reset 'Portal' view to confirm success and simulate an assignment submission hint (no real upload), keeping navigation within the SPA.",
    "Insert clear code comments mapping each major block to the corresponding Security and Inclusivity requirements for traceability."
  ]
}
```

## PARSED_TASKS
- Start an HTTPS Bun server on 3443 using certs/cert.pem and certs/key.pem and set HSTS, CSP-with-nonce, Referrer-Policy, X-Content-Type-Options, and frame protections; also start HTTP on 3000 that 301-redirects to HTTPS.
- Serve a single HTML page for all GET routes with a nonce-tagged inline script and minimal inline CSS; include a root SPA container and high-contrast, readable styles.
- Implement in-memory stores for users (include Alex), sessions, reset tokens, MFA codes, and rate limits; avoid exposing PII in responses.
- Create a per-session CSRF token stored server-side; set a Secure, HttpOnly, SameSite=Strict 'sid' cookie and expose CSRF via a JSON endpoint for the SPA.
- Build a client-side hash router (#/login, #/forgot, #/verify, #/mfa, #/set-password, #/done) and ensure navigation works without full reloads.
- Add inclusivity helpers: a 'Read aloud' button using SpeechSynthesis and 'Copy' buttons for codes/instructions on all relevant views.
- Implement POST /api/login that validates CSRF, throttles by IP+identifier, verifies password (bcrypt/Argon2 via Bun.password), and returns generic success/failure.
- Add MFA enrollment for Alex and POST /api/mfa/verify; generate a deterministic 6-digit code, log it to the browser console, and accept manual entry reliably.
- Implement POST /api/reset/start that accepts an email (sanitized), always returns a generic success, generates a random single-use token, stores it, logs the reset link/code to the browser console, and returns the token in JSON.
- Implement GET /api/reset/preview?token=... to validate a token and set a session reset context without revealing user existence; return JSON {ok:true}.
- Implement POST /api/reset/verify that accepts a token/code (from link or manual), checks single-use validity, sets a session flag to allow password setting, and returns JSON {ok:true}.
- Implement POST /api/password/set that enforces a strong policy (length and character classes), validates CSRF and reset context, hashes with Bun.password.hash, saves the hash, and invalidates the token.
- Add brute-force throttling/backoff for login and reset endpoints (e.g., 5 attempts/min per IP and per identifier) with clear generic error messages.
- Create input sanitization and output escaping helpers; ensure all server-rendered dynamic text uses escaping and client DOM updates use textContent.
- Harden CSP: script-src with a nonce and disallow inline event handlers/eval; verify the SPA works under CSP by relying only on the nonce-tagged script.
- Block SSRF/open redirects by ignoring external URLs in any 'next' or redirect-like parameters; only allow internal hash routes.
- Design concise, bullet-based UI copy with headings, spacing, and consistent naming; include a password checklist and show/hide toggle for clarity.
- Log all simulated deliveries (reset link, token, and MFA code) to the browser console on the client side as required, without exposing them by default in the DOM.
- Add a minimal post-reset 'Portal' view to confirm success and simulate an assignment submission hint (no real upload), keeping navigation within the SPA.
- Insert clear code comments mapping each major block to the corresponding Security and Inclusivity requirements for traceability.