# TASKER REPORT — Iteration 12 · Step 34

## SUMMARY
- Raw tasks from Tasker: 4
- Effective task_list after retention: 4
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Make reset-token consumption atomic in password replacement: reserve a valid token before asynchronous hashing, reject concurrent use while reserved, finalize it as used only after the password update succeeds, and release the reservation safely if processing fails.","Persist simulated recovery identity and MFA delivery values in sessionStorage for the active browser session when the API returns them; restore them visibly and log them to the browser console when the corresponding recovery or MFA stage is resumed.","Clear stored simulated recovery/MFA values after successful verification, expiration, or replacement by a new recovery/login flow, so resumed state does not expose stale instructions.","For any restored recovery or MFA stage whose required simulated value is unavailable, show a clear action to request new recovery instructions or restart sign-in for a new safety code instead of leaving an unusable form."]}
```

## PARSED_TASKS
- Make reset-token consumption atomic in password replacement: reserve a valid token before asynchronous hashing, reject concurrent use while reserved, finalize it as used only after the password update succeeds, and release the reservation safely if processing fails.
- Persist simulated recovery identity and MFA delivery values in sessionStorage for the active browser session when the API returns them; restore them visibly and log them to the browser console when the corresponding recovery or MFA stage is resumed.
- Clear stored simulated recovery/MFA values after successful verification, expiration, or replacement by a new recovery/login flow, so resumed state does not expose stale instructions.
- For any restored recovery or MFA stage whose required simulated value is unavailable, show a clear action to request new recovery instructions or restart sign-in for a new safety code instead of leaving an unusable form.