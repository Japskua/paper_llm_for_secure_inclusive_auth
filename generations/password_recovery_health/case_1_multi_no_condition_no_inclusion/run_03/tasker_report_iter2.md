# TASKER REPORT — Iteration 2 · Step 4

## SUMMARY
- Raw tasks from Tasker: 4
- Effective task_list after retention: 4
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Add distinct reset-record state for token consumption and password-update completion so token verification and password submission can be authorized independently.","On the first successful `/api/verify-reset` request, atomically consume the valid unexpired token before issuing its MFA challenge.","Make repeated `/api/verify-reset` submissions for a consumed token return the existing invalid, expired, or used response without creating or replacing MFA state.","Update `/api/password` to permit the completed verified-and-MFA-authorized recovery state after token consumption, while rejecting duplicate password updates with a separate completion guard."]}
```

## PARSED_TASKS
- Add distinct reset-record state for token consumption and password-update completion so token verification and password submission can be authorized independently.
- On the first successful /api/verify-reset request, atomically consume the valid unexpired token before issuing its MFA challenge.
- Make repeated /api/verify-reset submissions for a consumed token return the existing invalid, expired, or used response without creating or replacing MFA state.
- Update /api/password to permit the completed verified-and-MFA-authorized recovery state after token consumption, while rejecting duplicate password updates with a separate completion guard.