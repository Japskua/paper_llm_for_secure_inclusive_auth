# TASKER REPORT — Iteration 4 · Step 10

## SUMMARY
- Raw tasks from Tasker: 3
- Effective task_list after retention: 3
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Update recovery-code validation so it exactly accepts the recovery-code alphabet produced by randomRecoveryCode(), including 8 and 9 and excluding disallowed ambiguous letters if intended.","Add strict, bounded server-side email and phone validation before creating an identity target or storing an identityStates entry; reject malformed values with the existing generic response behavior.","Rotate the session identifier after successful /api/identity/verify authentication, transfer only the required authenticated state to the new session, delete the old session, issue a new secure cookie, and return the replacement CSRF token to the client."]}
```

## PARSED_TASKS
- Update recovery-code validation so it exactly accepts the recovery-code alphabet produced by randomRecoveryCode(), including 8 and 9 and excluding disallowed ambiguous letters if intended.
- Add strict, bounded server-side email and phone validation before creating an identity target or storing an identityStates entry; reject malformed values with the existing generic response behavior.
- Rotate the session identifier after successful /api/identity/verify authentication, transfer only the required authenticated state to the new session, delete the old session, issue a new secure cookie, and return the replacement CSRF token to the client.