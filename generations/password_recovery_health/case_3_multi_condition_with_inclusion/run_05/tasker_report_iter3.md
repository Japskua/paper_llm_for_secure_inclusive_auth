# TASKER REPORT — Iteration 3 · Step 7

## SUMMARY
- Raw tasks from Tasker: 4
- Effective task_list after retention: 4
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Clear `authenticated` and `privacyAccepted` when a recovery request starts and again before setting `pendingMfa` after a password update; ensure only successful MFA can establish authenticated state.","Enforce `SESSION_MAX_AGE` in `sessionFor()` by deleting expired server-side session records and creating a new session instead of accepting an expired session ID.","Provide and visibly document a clearly synthetic approved demo identifier in the browser UI so a tester can complete the recovery flow without using or exposing real patient data.","Make approved and unapproved recovery API responses have the same externally observable status, message, and response shape; expose the mock recovery code only through a controlled demo mechanism that does not reveal account approval status."]}
```

## PARSED_TASKS
- Clear authenticated and privacyAccepted when a recovery request starts and again before setting pendingMfa after a password update; ensure only successful MFA can establish authenticated state.
- Enforce `SESSION_MAX_AGE` in sessionFor() by deleting expired server-side session records and creating a new session instead of accepting an expired session ID.
- Provide and visibly document a clearly synthetic approved demo identifier in the browser UI so a tester can complete the recovery flow without using or exposing real patient data.
- Make approved and unapproved recovery API responses have the same externally observable status, message, and response shape; expose the mock recovery code only through a controlled demo mechanism that does not reveal account approval status.