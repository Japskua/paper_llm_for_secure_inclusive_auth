# TASKER REPORT — Iteration 4 · Step 10

## SUMMARY
- Raw tasks from Tasker: 2
- Effective task_list after retention: 2
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["In the verify-token action, compare the submitted token length to session.resetToken.length before calling crypto.timingSafeEqual; treat unequal lengths as an ordinary invalid token attempt.","Ensure all invalid token values, including valid-format values with a wrong length, call failedAttempt(session, \"token\") and return the normal invalid-token response rather than allowing an exception to reach the top-level error handler."]}
```

## PARSED_TASKS
- In the verify-token action, compare the submitted token length to session.resetToken.length before calling crypto.timingSafeEqual; treat unequal lengths as an ordinary invalid token attempt.
- Ensure all invalid token values, including valid-format values with a wrong length, call failedAttempt(session, "token") and return the normal invalid-token response rather than allowing an exception to reach the top-level error handler.