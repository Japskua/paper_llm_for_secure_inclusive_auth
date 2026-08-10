# TASKER REPORT — Iteration 4 · Step 10

## SUMMARY
- Raw tasks from Tasker: 3
- Effective task_list after retention: 3
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Make MFA provisioning verification single-use atomically: reserve or mark the pending challenge consumed before asynchronous decrypt/TOTP validation, restore it only if appropriate on a failed validation, and ensure only one successful request can issue recovery codes.","Update sign-in, identity-code verification, authenticator-code verification, and recovery-code verification so every authenticated failed verification attempt—including structurally invalid entries—contributes to the applicable rate-limit/lockout counter while retaining generic error responses.","Add lock-expiry handling that resets loginFailures, identityFailures, and MFA session failure counts when their corresponding lock period has elapsed, before processing the next attempt."]}
```

## PARSED_TASKS
- Make MFA provisioning verification single-use atomically: reserve or mark the pending challenge consumed before asynchronous decrypt/TOTP validation, restore it only if appropriate on a failed validation, and ensure only one successful request can issue recovery codes.
- Update sign-in, identity-code verification, authenticator-code verification, and recovery-code verification so every authenticated failed verification attempt—including structurally invalid entries—contributes to the applicable rate-limit/lockout counter while retaining generic error responses.
- Add lock-expiry handling that resets loginFailures, identityFailures, and MFA session failure counts when their corresponding lock period has elapsed, before processing the next attempt.