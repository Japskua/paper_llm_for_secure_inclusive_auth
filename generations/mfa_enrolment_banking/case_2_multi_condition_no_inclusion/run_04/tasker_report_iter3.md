# TASKER REPORT — Iteration 3 · Step 7

## SUMMARY
- Raw tasks from Tasker: 3
- Effective task_list after retention: 3
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Make `/api/mfa/confirm` atomic for each MFA draft: synchronously reserve the draft before its first asynchronous operation, reject concurrent confirmations, and release the reservation only after validation failure, expiry, or an unexpected error.","On successful atomic MFA confirmation, consume the draft and generate/store exactly one recovery-code set before responding; prevent any later or concurrent request from overwriting the active hashed recovery codes or returning another successful code set.","Add a documented manual regression scenario in `app.ts` that submits two simultaneous valid `/api/mfa/confirm` requests for one draft and verifies that exactly one succeeds and only its recovery-code set is active."]}
```

## PARSED_TASKS
- Make /api/mfa/confirm atomic for each MFA draft: synchronously reserve the draft before its first asynchronous operation, reject concurrent confirmations, and release the reservation only after validation failure, expiry, or an unexpected error.
- On successful atomic MFA confirmation, consume the draft and generate/store exactly one recovery-code set before responding; prevent any later or concurrent request from overwriting the active hashed recovery codes or returning another successful code set.
- Add a documented manual regression scenario in app.ts that submits two simultaneous valid /api/mfa/confirm requests for one draft and verifies that exactly one succeeds and only its recovery-code set is active.