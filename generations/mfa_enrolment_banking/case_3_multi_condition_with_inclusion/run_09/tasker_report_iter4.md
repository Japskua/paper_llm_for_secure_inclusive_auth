# TASKER REPORT — Iteration 4 · Step 10

## SUMMARY
- Raw tasks from Tasker: 5
- Effective task_list after retention: 5
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Generate a cryptographically random six-digit identity code for every successful sign-in and every resend; ensure a resent code differs from the invalidated prior code.","Store only a protected server-side representation of each identity code with its expiry, used status, and failed-attempt count; reject expired, used, or incorrect codes.","Make the resend endpoint invalidate the previous identity code before issuing the replacement, and return only the new mock code in the authenticated API response for browser-side console logging.","Replace recovery-code salted SHA-256 storage with a slow password KDF using unique per-code salts while preserving one-time-use tracking and recovery-code verification.","Keep all identity-code and recovery-code plaintext out of server logs, URLs, errors, browser storage, and non-HttpOnly cookies."]}
```

## PARSED_TASKS
- Generate a cryptographically random six-digit identity code for every successful sign-in and every resend; ensure a resent code differs from the invalidated prior code.
- Store only a protected server-side representation of each identity code with its expiry, used status, and failed-attempt count; reject expired, used, or incorrect codes.
- Make the resend endpoint invalidate the previous identity code before issuing the replacement, and return only the new mock code in the authenticated API response for browser-side console logging.
- Replace recovery-code salted SHA-256 storage with a slow password KDF using unique per-code salts while preserving one-time-use tracking and recovery-code verification.
- Keep all identity-code and recovery-code plaintext out of server logs, URLs, errors, browser storage, and non-HttpOnly cookies.