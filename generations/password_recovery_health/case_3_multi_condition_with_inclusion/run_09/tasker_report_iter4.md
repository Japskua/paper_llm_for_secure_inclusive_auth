# TASKER REPORT — Iteration 4 · Step 10

## SUMMARY
- Raw tasks from Tasker: 3
- Effective task_list after retention: 3
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Make reset-token verification single-use by recording server-side token consumption when verification succeeds and rejecting every later verification attempt for that token, while preserving the verified state required for MFA and password update.","Persist a server-authoritative post-password-update, pre-login state so bootstrap and stage resolution return the sign-in step after refresh or return, and allow sign-in using the newly updated password.","Add regression checks confirming a reset token is rejected on second submission, a refresh after password update restores sign-in and permits login, and login followed by privacy acceptance reaches and retains the completion screen."]}
```

## PARSED_TASKS
- Make reset-token verification single-use by recording server-side token consumption when verification succeeds and rejecting every later verification attempt for that token, while preserving the verified state required for MFA and password update.
- Persist a server-authoritative post-password-update, pre-login state so bootstrap and stage resolution return the sign-in step after refresh or return, and allow sign-in using the newly updated password.
- Add regression checks confirming a reset token is rejected on second submission, a refresh after password update restores sign-in and permits login, and login followed by privacy acceptance reaches and retains the completion screen.