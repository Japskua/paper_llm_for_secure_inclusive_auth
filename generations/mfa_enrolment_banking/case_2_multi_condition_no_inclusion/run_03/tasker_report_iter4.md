# TASKER REPORT — Iteration 4 · Step 10

## SUMMARY
- Raw tasks from Tasker: 3
- Effective task_list after retention: 3
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Make identity-code consumption atomic in `/api/auth/identity`: after asynchronous hash comparison, immediately re-check session stage, expiry, lock status, and `identityUsed`, then set `identityUsed = true` synchronously before any further await; reject already reserved or consumed codes.","Make TOTP verification atomic in `/api/mfa/verify`: calculate candidate TOTP values, then immediately re-check and synchronously reserve the matching counter in `acceptedTotpCounters` before any subsequent asynchronous operation; reject a counter already reserved by a concurrent request.","Ensure only the request that atomically reserves a TOTP counter can enable MFA and generate/store recovery codes; concurrent requests using that same code must receive a generic verification failure and no recovery-code response."]}
```

## PARSED_TASKS
- Make identity-code consumption atomic in /api/auth/identity: after asynchronous hash comparison, immediately re-check session stage, expiry, lock status, and identityUsed, then set identityUsed = true synchronously before any further await; reject already reserved or consumed codes.
- Make TOTP verification atomic in /api/mfa/verify: calculate candidate TOTP values, then immediately re-check and synchronously reserve the matching counter in acceptedTotpCounters before any subsequent asynchronous operation; reject a counter already reserved by a concurrent request.
- Ensure only the request that atomically reserves a TOTP counter can enable MFA and generate/store recovery codes; concurrent requests using that same code must receive a generic verification failure and no recovery-code response.