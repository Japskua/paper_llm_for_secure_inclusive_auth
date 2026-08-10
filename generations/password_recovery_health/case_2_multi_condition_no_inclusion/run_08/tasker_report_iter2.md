# TASKER REPORT — Iteration 2 · Step 4

## SUMMARY
- Raw tasks from Tasker: 4
- Effective task_list after retention: 4
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Add reset-token consumption and short-lived verified-reset authorization state to each session; initialize or clear both whenever a recovery request is created or restarted.","On successful reset-token verification, consume the token immediately so it cannot be verified again, clear its stored hash, and create the short-lived authorization required for password submission.","Require the password-update endpoint to validate the unexpired verified-reset authorization instead of the original reset-token record.","Ensure reused consumed tokens fail, expired reset authorization cannot update a password, and issuance of a new recovery token cleanly resets recovery state."]}
```

## PARSED_TASKS
- Add reset-token consumption and short-lived verified-reset authorization state to each session; initialize or clear both whenever a recovery request is created or restarted.
- On successful reset-token verification, consume the token immediately so it cannot be verified again, clear its stored hash, and create the short-lived authorization required for password submission.
- Require the password-update endpoint to validate the unexpired verified-reset authorization instead of the original reset-token record.
- Ensure reused consumed tokens fail, expired reset authorization cannot update a password, and issuance of a new recovery token cleanly resets recovery state.