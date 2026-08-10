# TASKER REPORT — Iteration 2 · Step 4

## SUMMARY
- Raw tasks from Tasker: 2
- Effective task_list after retention: 2
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Add a CSRF-protected POST /api/recovery-reset endpoint that clears the current session’s recoveryId (and preferably rotates the session CSRF token), then update both “Start over” links to call it, set serverStage to \"request\", and navigate to #request.","Change the recovery model to store a pendingPasswordHash after /api/set-password; only move it to the final password-hash field and mark the recovery completed after /api/verify-mfa succeeds. Ensure failed, expired, or locked MFA attempts cannot finalize or activate the pending password change."]}
```

## PARSED_TASKS
- Add a CSRF-protected POST /api/recovery-reset endpoint that clears the current session’s recoveryId (and preferably rotates the session CSRF token), then update both “Start over” links to call it, set serverStage to "request", and navigate to #request.
- Change the recovery model to store a pendingPasswordHash after /api/set-password; only move it to the final password-hash field and mark the recovery completed after /api/verify-mfa succeeds. Ensure failed, expired, or locked MFA attempts cannot finalize or activate the pending password change.