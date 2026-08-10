# TASKER REPORT — Iteration 2 · Step 4

## SUMMARY
- Raw tasks from Tasker: 3
- Effective task_list after retention: 3
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Add an expiration timestamp for the verified recovery flow to Session and enforce it in /api/reset; clear flowId and reject the reset when the verified flow has expired.","Add server-side verification attempt rate limiting that applies even when a submitted reset token does not exist, using a bounded server-side key such as client IP plus session ID, with a defined window and temporary block period.","Add server-side recovery-request rate limiting that cannot be bypassed merely by obtaining a new session, such as a bounded IP-based limiter in addition to the existing per-session limiter."]}
```

## PARSED_TASKS
- Add an expiration timestamp for the verified recovery flow to Session and enforce it in /api/reset; clear flowId and reject the reset when the verified flow has expired.
- Add server-side verification attempt rate limiting that applies even when a submitted reset token does not exist, using a bounded server-side key such as client IP plus session ID, with a defined window and temporary block period.
- Add server-side recovery-request rate limiting that cannot be bypassed merely by obtaining a new session, such as a bounded IP-based limiter in addition to the existing per-session limiter.