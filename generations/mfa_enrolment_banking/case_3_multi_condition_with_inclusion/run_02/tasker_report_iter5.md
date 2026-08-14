# TASKER REPORT — Iteration 5 · Step 13

## SUMMARY
- Raw tasks from Tasker: 4
- Effective task_list after retention: 4
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Add a server-side helper that removes every session for a specified authenticated user, with an optional session ID to preserve.","On successful sign-in, invalidate all existing sessions for the account before storing the newly generated session ID.","On logout, invalidate every active session belonging to the authenticated account and clear the current session cookie.","Verify that a previously issued session cookie is rejected by `/api/state`, `/api/mfa/verify`, and all MFA-changing endpoints after either a new sign-in or logout."]}
```

## PARSED_TASKS
- Add a server-side helper that removes every session for a specified authenticated user, with an optional session ID to preserve.
- On successful sign-in, invalidate all existing sessions for the account before storing the newly generated session ID.
- On logout, invalidate every active session belonging to the authenticated account and clear the current session cookie.
- Verify that a previously issued session cookie is rejected by /api/state, /api/mfa/verify, and all MFA-changing endpoints after either a new sign-in or logout.