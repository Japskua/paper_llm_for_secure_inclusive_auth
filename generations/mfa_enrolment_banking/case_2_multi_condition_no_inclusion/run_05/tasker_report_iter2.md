# TASKER REPORT — Iteration 2 · Step 4

## SUMMARY
- Raw tasks from Tasker: 2
- Effective task_list after retention: 2
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Add recovery-code verification failure tracking and lockout enforcement. Add `recoveryFailures` and `recoveryLockUntil` to the session, reject locked sessions before verification, count every malformed, used, invalid, or non-matching recovery-code submission, lock after the configured threshold using `LOCKOUT_MS`, and reset the counter only after successful verification.","Ensure every failed TOTP activation submission contributes to lockout. Check `totpLockUntil` before validation, count malformed as well as incorrect six-digit OTP submissions toward `totpFailures`, apply lockout at the configured threshold, and reset failures only after successful authenticator activation."]}
```

## PARSED_TASKS
- Add recovery-code verification failure tracking and lockout enforcement. Add recoveryFailures and recoveryLockUntil to the session, reject locked sessions before verification, count every malformed, used, invalid, or non-matching recovery-code submission, lock after the configured threshold using `LOCKOUT_MS`, and reset the counter only after successful verification.
- Ensure every failed TOTP activation submission contributes to lockout. Check totpLockUntil before validation, count malformed as well as incorrect six-digit OTP submissions toward totpFailures, apply lockout at the configured threshold, and reset failures only after successful authenticator activation.