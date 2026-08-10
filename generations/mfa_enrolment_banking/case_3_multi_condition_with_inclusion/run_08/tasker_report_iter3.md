# TASKER REPORT — Iteration 3 · Step 7

## SUMMARY
- Raw tasks from Tasker: 3
- Effective task_list after retention: 3
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Require the sign-in email to match the mock account identity before any session for that account is created, and return the same generic response for unknown or invalid account identities.","Bind the mock identity-verification challenge to the validated account and authorize MFA access only after that challenge is successfully verified.","Rate-limit recovery-code verification by tracking failed attempts per session, locking recovery verification for `LOCK_MS` after `MAX_FAILURES` invalid, used, or non-matching codes, and resetting the counter after a successful verification."]}
```

## PARSED_TASKS
- Require the sign-in email to match the mock account identity before any session for that account is created, and return the same generic response for unknown or invalid account identities.
- Bind the mock identity-verification challenge to the validated account and authorize MFA access only after that challenge is successfully verified.
- Rate-limit recovery-code verification by tracking failed attempts per session, locking recovery verification for `LOCK_MS` after `MAX_FAILURES` invalid, used, or non-matching codes, and resetting the counter after a successful verification.