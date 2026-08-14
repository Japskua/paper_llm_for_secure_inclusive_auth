# TASKER REPORT — Iteration 9 · Step 25

## SUMMARY
- Raw tasks from Tasker: 5
- Effective task_list after retention: 5
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Make identity-verification lockout account/session scoped and preserve it when a new identity code is requested; reject re-requests until lockedUntil has passed.","Remove the authFailures and authLockedUntil reset from /api/authenticator/provision; only clear failed-attempt state after a successful authenticator confirmation or after the lockout expires.","Add an owner-authorized, CSRF-protected recovery-code verification endpoint that validates the recovery-code format, compares salted hashes in constant time, marks a matching code as used, rejects reused codes, and applies rate limiting/lockout.","Add a corresponding recovery-code entry UI with clear plain-language feedback for valid, invalid, used, and locked-out recovery-code attempts.","Remove sensitive OTP and recovery-code values from the on-page activity-log panel. Keep the required demo console.log output in the browser, and show codes only in the purpose-specific protected setup/recovery screens."]}
```

## PARSED_TASKS
- Make identity-verification lockout account/session scoped and preserve it when a new identity code is requested; reject re-requests until lockedUntil has passed.
- Remove the authFailures and authLockedUntil reset from /api/authenticator/provision; only clear failed-attempt state after a successful authenticator confirmation or after the lockout expires.
- Add an owner-authorized, CSRF-protected recovery-code verification endpoint that validates the recovery-code format, compares salted hashes in constant time, marks a matching code as used, rejects reused codes, and applies rate limiting/lockout.
- Add a corresponding recovery-code entry UI with clear plain-language feedback for valid, invalid, used, and locked-out recovery-code attempts.
- Remove sensitive OTP and recovery-code values from the on-page activity-log panel. Keep the required demo console.log output in the browser, and show codes only in the purpose-specific protected setup/recovery screens.