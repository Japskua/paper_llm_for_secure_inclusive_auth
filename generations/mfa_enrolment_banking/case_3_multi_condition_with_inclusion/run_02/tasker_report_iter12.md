# TASKER REPORT — Iteration 12 · Step 34

## SUMMARY
- Raw tasks from Tasker: 20
- Effective task_list after retention: 20
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Complete app.ts as syntactically valid TypeScript, including the unfinished headers function and all required closing implementation.",
    "Create a single Bun HTTPS server in app.ts that loads certs/cert.pem and certs/key.pem, serves the application, and returns generic non-verbose error responses.",
    "Add secure response headers to every response: CSP with a per-response script nonce, HSTS, X-Content-Type-Options: nosniff, and clickjacking protection using frame-ancestors 'none' and/or X-Frame-Options: DENY.",
    "Restrict cross-origin requests to the trusted local application origin and reject unsupported origins rather than reflecting arbitrary Origin headers.",
    "Add one inline HTML document with semantic structure, viewport metadata, responsive mobile CSS, and vanilla browser JavaScript only.",
    "Implement a readable, dyslexia-inclusive interface with short plain-language instructions, legible spacing and type, stable screens, visible current-step status, examples for code inputs, accessible hints, and one prominent primary action per screen.",
    "Implement functioning browser navigation for sign-in, identity verification, authenticator setup, authenticator verification, recovery-code review, enrolment confirmation, recovery-code use, backup-code regeneration, and logout without broken internal links.",
    "Implement session establishment with session-ID rotation, secure HttpOnly Secure SameSite=Strict cookies, idle and absolute session expiry checks, and logout invalidation with cookie clearing.",
    "Require an authenticated valid session on every MFA API endpoint and derive the account solely from that session; do not accept any client-supplied user identifier as authorization.",
    "Issue an anti-CSRF token to the authenticated browser and require it with same-origin Origin validation on every state-changing endpoint.",
    "Implement validation for all submitted identity, OTP, TOTP, and recovery-code inputs; return specific safe fix-oriented validation errors and safely encode all rendered or returned data.",
    "Implement simulated identity-code issuing, re-requesting, and verification with cryptographically strong values, time bounds, single-use behavior, and browser-console logging of only the explicit test mock code.",
    "Implement authenticator provisioning that returns a manual secret and provisioning URI, provides an accessible QR representation and copy controls, and logs the explicit mock provisioning values only in the browser console.",
    "Store TOTP secrets encrypted at rest, verify submitted time-based OTPs, and prevent reuse of a successfully accepted OTP counter.",
    "Generate recovery codes with cryptographically secure randomness, store only salted strong hashes, display plaintext codes only at creation or regeneration, and support copy/download plus acknowledgement before enrolment completes.",
    "Implement recovery-code verification so a successfully used code cannot be used again, and provide a protected backup-code regeneration flow.",
    "Add per-account failed-code attempt tracking with rate limiting and a five-minute lockout; reset the relevant failure count only after successful verification.",
    "Ensure no session IDs, CSRF tokens, stored encrypted secrets, hashes, or non-mock verification values appear in URLs, server logs, error output, or browser storage.",
    "Use an allow-list of internal destinations for any redirect behavior and reject external or malformed redirect targets.",
    "Require a stable valid 32-byte MFA_SERVER_KEY when encrypted MFA records must survive server restarts; fail safely with a generic configuration error rather than silently using an unrecoverable process-only key."
  ]
}
```

## PARSED_TASKS
- Complete app.ts as syntactically valid TypeScript, including the unfinished headers function and all required closing implementation.
- Create a single Bun HTTPS server in app.ts that loads certs/cert.pem and certs/key.pem, serves the application, and returns generic non-verbose error responses.
- Add secure response headers to every response: CSP with a per-response script nonce, HSTS, X-Content-Type-Options: nosniff, and clickjacking protection using frame-ancestors 'none' and/or X-Frame-Options: DENY.
- Restrict cross-origin requests to the trusted local application origin and reject unsupported origins rather than reflecting arbitrary Origin headers.
- Add one inline HTML document with semantic structure, viewport metadata, responsive mobile CSS, and vanilla browser JavaScript only.
- Implement a readable, dyslexia-inclusive interface with short plain-language instructions, legible spacing and type, stable screens, visible current-step status, examples for code inputs, accessible hints, and one prominent primary action per screen.
- Implement functioning browser navigation for sign-in, identity verification, authenticator setup, authenticator verification, recovery-code review, enrolment confirmation, recovery-code use, backup-code regeneration, and logout without broken internal links.
- Implement session establishment with session-ID rotation, secure HttpOnly Secure SameSite=Strict cookies, idle and absolute session expiry checks, and logout invalidation with cookie clearing.
- Require an authenticated valid session on every MFA API endpoint and derive the account solely from that session; do not accept any client-supplied user identifier as authorization.
- Issue an anti-CSRF token to the authenticated browser and require it with same-origin Origin validation on every state-changing endpoint.
- Implement validation for all submitted identity, OTP, TOTP, and recovery-code inputs; return specific safe fix-oriented validation errors and safely encode all rendered or returned data.
- Implement simulated identity-code issuing, re-requesting, and verification with cryptographically strong values, time bounds, single-use behavior, and browser-console logging of only the explicit test mock code.
- Implement authenticator provisioning that returns a manual secret and provisioning URI, provides an accessible QR representation and copy controls, and logs the explicit mock provisioning values only in the browser console.
- Store TOTP secrets encrypted at rest, verify submitted time-based OTPs, and prevent reuse of a successfully accepted OTP counter.
- Generate recovery codes with cryptographically secure randomness, store only salted strong hashes, display plaintext codes only at creation or regeneration, and support copy/download plus acknowledgement before enrolment completes.
- Implement recovery-code verification so a successfully used code cannot be used again, and provide a protected backup-code regeneration flow.
- Add per-account failed-code attempt tracking with rate limiting and a five-minute lockout; reset the relevant failure count only after successful verification.
- Ensure no session IDs, CSRF tokens, stored encrypted secrets, hashes, or non-mock verification values appear in URLs, server logs, error output, or browser storage.
- Use an allow-list of internal destinations for any redirect behavior and reject external or malformed redirect targets.
- Require a stable valid 32-byte MFA_SERVER_KEY when encrypted MFA records must survive server restarts; fail safely with a generic configuration error rather than silently using an unrecoverable process-only key.