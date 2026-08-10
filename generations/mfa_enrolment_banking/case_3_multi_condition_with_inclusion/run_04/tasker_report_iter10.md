# TASKER REPORT — Iteration 10 · Step 28

## SUMMARY
- Raw tasks from Tasker: 8
- Effective task_list after retention: 8
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Add failed sign-in attempt tracking and temporary lockout to `/api/sign-in`, keyed per session and/or account, while returning generic non-enumerating failure messages.",
    "Add a CSRF-protected, authorized server endpoint for recovery-code verification that validates the code format, safely compares its hash, consumes a matched code, and enforces failure lockout through `recoveryFails` and `recoveryLockedUntil`.",
    "Add a recovery-code verification screen and route that lets an authenticated user submit a generated recovery code and plainly confirms whether it was accepted or already used.",
    "Replace the placeholder `qr(uri)` grid with an inline browser-side standards-compliant QR encoder that renders a scannable QR code for the displayed authenticator provisioning URI.",
    "Add authenticator setup controls to hide and reveal the manual secret and provisioning URI without removing copy functionality.",
    "Add a clearly labeled “Show new setup details” action that replaces an active pending authenticator setup secret and returns the new mock provisioning details to the browser console.",
    "Add a consistent, concise help or hint control on every enrolment screen, including sign-in and completion, using plain language and low-reading-load guidance.",
    "Add adjacent code comments mapping authorization and CSRF, TLS and security headers, secret storage, input validation and output encoding, and verification/lockout behavior to Security Requirements 1–5."
  ]
}
```

## PARSED_TASKS
- Add failed sign-in attempt tracking and temporary lockout to /api/sign-in, keyed per session and/or account, while returning generic non-enumerating failure messages.
- Add a CSRF-protected, authorized server endpoint for recovery-code verification that validates the code format, safely compares its hash, consumes a matched code, and enforces failure lockout through recoveryFails and recoveryLockedUntil.
- Add a recovery-code verification screen and route that lets an authenticated user submit a generated recovery code and plainly confirms whether it was accepted or already used.
- Replace the placeholder qr(uri) grid with an inline browser-side standards-compliant QR encoder that renders a scannable QR code for the displayed authenticator provisioning URI.
- Add authenticator setup controls to hide and reveal the manual secret and provisioning URI without removing copy functionality.
- Add a clearly labeled “Show new setup details” action that replaces an active pending authenticator setup secret and returns the new mock provisioning details to the browser console.
- Add a consistent, concise help or hint control on every enrolment screen, including sign-in and completion, using plain language and low-reading-load guidance.
- Add adjacent code comments mapping authorization and CSRF, TLS and security headers, secret storage, input validation and output encoding, and verification/lockout behavior to Security Requirements 1–5.