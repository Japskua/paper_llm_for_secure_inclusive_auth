# TASKER REPORT — Iteration 3 · Step 7

## SUMMARY
- Raw tasks from Tasker: 3
- Effective task_list after retention: 3
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Update `/api/auth/verify` so invalid or missing identity-code formats are counted after session/CSRF validation and identity-throttle retrieval; lock out after the existing failure threshold just as for expired or incorrect codes.","Update `/api/mfa/confirm` so invalid or missing authenticator OTP formats are counted after ownership/CSRF validation and authenticator-throttle retrieval; preserve lockout handling for expired, reused, and incorrect OTPs.","Update `/api/mfa/recovery/verify` so invalid or missing recovery-code formats are counted after ownership/CSRF validation, MFA-record lookup, and lock-state checking; preserve existing lock duration and reset failures after successful code use."]}
```

## PARSED_TASKS
- Update /api/auth/verify so invalid or missing identity-code formats are counted after session/CSRF validation and identity-throttle retrieval; lock out after the existing failure threshold just as for expired or incorrect codes.
- Update /api/mfa/confirm so invalid or missing authenticator OTP formats are counted after ownership/CSRF validation and authenticator-throttle retrieval; preserve lockout handling for expired, reused, and incorrect OTPs.
- Update /api/mfa/recovery/verify so invalid or missing recovery-code formats are counted after ownership/CSRF validation, MFA-record lookup, and lock-state checking; preserve existing lock duration and reset failures after successful code use.