# TASKER REPORT — Iteration 3 · Step 7

## SUMMARY
- Raw tasks from Tasker: 5
- Effective task_list after retention: 5
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Add an expiresAt timestamp to each server-side session when it is created, and reject and delete expired sessions before serving pages or processing API actions.","Perform opportunistic cleanup of expired session and reset records on incoming requests.","Replace the global password hash with password state stored in an internal account record keyed by a non-exposed account identifier.","Bind every recovery reset record and authenticated session to its internal account identifier, and verify sign-in only against that account's password hash.","Verify that resetting a password in one account or recovery context cannot change password verification or sign-in behavior for any other account or session."]}
```

## PARSED_TASKS
- Add an expiresAt timestamp to each server-side session when it is created, and reject and delete expired sessions before serving pages or processing API actions.
- Perform opportunistic cleanup of expired session and reset records on incoming requests.
- Replace the global password hash with password state stored in an internal account record keyed by a non-exposed account identifier.
- Bind every recovery reset record and authenticated session to its internal account identifier, and verify sign-in only against that account's password hash.
- Verify that resetting a password in one account or recovery context cannot change password verification or sign-in behavior for any other account or session.