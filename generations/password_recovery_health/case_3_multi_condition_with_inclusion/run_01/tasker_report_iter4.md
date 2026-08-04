# TASKER REPORT — Iteration 4 · Step 10

## SUMMARY
- Raw tasks from Tasker: 2
- Effective task_list after retention: 2
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Change `/api/verify-reset` throttling to use a non-attacker-controlled key, such as the client IP plus session ID (or at minimum client IP), rather than the submitted reset token. Keep the existing successful-verification limit clearing aligned with the new key.","Change `/api/mfa` throttling to use a non-attacker-controlled key, such as the client IP plus session ID or the authenticated/pre-MFA account/session context, rather than the submitted MFA code. Ensure all incorrect code attempts for the same MFA challenge contribute to the same limit."]}
```

## PARSED_TASKS
- Change /api/verify-reset throttling to use a non-attacker-controlled key, such as the client IP plus session ID (or at minimum client IP), rather than the submitted reset token. Keep the existing successful-verification limit clearing aligned with the new key.
- Change /api/mfa throttling to use a non-attacker-controlled key, such as the client IP plus session ID or the authenticated/pre-MFA account/session context, rather than the submitted MFA code. Ensure all incorrect code attempts for the same MFA challenge contribute to the same limit.