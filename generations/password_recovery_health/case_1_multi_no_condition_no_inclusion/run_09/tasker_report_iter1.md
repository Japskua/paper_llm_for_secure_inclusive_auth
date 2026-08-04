# TASKER REPORT — Iteration 1 · Step 1

## SUMMARY
- Raw tasks from Tasker: 12
- Effective task_list after retention: 12
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Create a single runnable `app.ts` that starts a Bun HTTPS server using `certs/cert.pem` and `certs/key.pem`, serves the complete inline HTML/CSS/vanilla-JS SPA, and has no local modules, build steps, frameworks, or external network calls.",
    "Implement HTTPS-only request handling with a safe HTTP rejection/redirect strategy, HSTS, CSP, secure cookie attributes, anti-framing and MIME-sniffing headers, generic production error responses, and no debug or directory exposure.",
    "Create server-side in-memory session state with cryptographically random session IDs and unique per-session CSRF tokens; require and validate the session CSRF token on every state-changing endpoint.",
    "Implement a privacy-preserving password-reset request endpoint that accepts an account email without disclosing whether it exists, rate-limits repeated requests, generates a cryptographically random short-lived single-use reset token for the mock account, and returns the token only for browser-console mock delivery.",
    "Implement reset-token validation and password-update endpoints that enforce token expiry and single use, bind reset state to the requesting session, rate-limit verification guesses, and return clear but non-sensitive status messages.",
    "Hash the replacement password using Bun-supported bcrypt or Argon2 before retaining it in mock state, and enforce a documented strong-password policy without logging or rendering the password value.",
    "Implement deterministic MFA verification after a valid password reset, with the mock code delivered only through browser `console.log`, a manual code-entry form, per-session attempt throttling, and a code that remains valid for the evaluation flow.",
    "Implement authenticated privacy-condition acceptance and appointment-confirmation endpoints that require the owning authenticated session and CSRF validation, expose no patient identifiers, and prevent IDOR through server-side session ownership checks.",
    "Build accessible semantic SPA screens for recovery request, reset-link/code entry, new password, MFA, privacy-condition acceptance, and appointment confirmation; make every internal navigation action functional through safe in-page state or implemented routes.",
    "Ensure all client-rendered dynamic values use safe DOM text APIs rather than HTML injection, validate inputs client- and server-side, avoid executing URL/input-derived scripts, and allow only fixed internal navigation targets to prevent XSS, phishing, and open redirects.",
    "Add visible safe-authentication guidance warning users not to share passwords or verification codes and to verify the localhost portal, while ensuring mocked delivery and flow events are logged with `console.log` in the browser only.",
    "Add concise code comments in `app.ts` mapping each security control and UI flow to the relevant numbered requirement sections."
  ]
}
```

## PARSED_TASKS
- Create a single runnable app.ts that starts a Bun HTTPS server using certs/cert.pem and certs/key.pem, serves the complete inline HTML/CSS/vanilla-JS SPA, and has no local modules, build steps, frameworks, or external network calls.
- Implement HTTPS-only request handling with a safe HTTP rejection/redirect strategy, HSTS, CSP, secure cookie attributes, anti-framing and MIME-sniffing headers, generic production error responses, and no debug or directory exposure.
- Create server-side in-memory session state with cryptographically random session IDs and unique per-session CSRF tokens; require and validate the session CSRF token on every state-changing endpoint.
- Implement a privacy-preserving password-reset request endpoint that accepts an account email without disclosing whether it exists, rate-limits repeated requests, generates a cryptographically random short-lived single-use reset token for the mock account, and returns the token only for browser-console mock delivery.
- Implement reset-token validation and password-update endpoints that enforce token expiry and single use, bind reset state to the requesting session, rate-limit verification guesses, and return clear but non-sensitive status messages.
- Hash the replacement password using Bun-supported bcrypt or Argon2 before retaining it in mock state, and enforce a documented strong-password policy without logging or rendering the password value.
- Implement deterministic MFA verification after a valid password reset, with the mock code delivered only through browser console.log, a manual code-entry form, per-session attempt throttling, and a code that remains valid for the evaluation flow.
- Implement authenticated privacy-condition acceptance and appointment-confirmation endpoints that require the owning authenticated session and CSRF validation, expose no patient identifiers, and prevent IDOR through server-side session ownership checks.
- Build accessible semantic SPA screens for recovery request, reset-link/code entry, new password, MFA, privacy-condition acceptance, and appointment confirmation; make every internal navigation action functional through safe in-page state or implemented routes.
- Ensure all client-rendered dynamic values use safe DOM text APIs rather than HTML injection, validate inputs client- and server-side, avoid executing URL/input-derived scripts, and allow only fixed internal navigation targets to prevent XSS, phishing, and open redirects.
- Add visible safe-authentication guidance warning users not to share passwords or verification codes and to verify the localhost portal, while ensuring mocked delivery and flow events are logged with console.log in the browser only.
- Add concise code comments in app.ts mapping each security control and UI flow to the relevant numbered requirement sections.