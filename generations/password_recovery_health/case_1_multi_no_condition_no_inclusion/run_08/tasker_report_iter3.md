# TASKER REPORT — Iteration 3 · Step 7

## SUMMARY
- Raw tasks from Tasker: 3
- Effective task_list after retention: 3
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Change `/api/verify` rate limiting to use an IP-based key that is not session-specific, or combine independent IP and session limits so creating a new session cannot reset the network-level verification attempt budget.","Enforce `verifiedFlowExpiresAt` in `/api/mfa`; when expired, clear the recovery flow and return a clear error requiring a new recovery request. Ensure subsequent state-dependent recovery endpoints use consistent expiration handling.","Add client-side route guards so `#reset`, `#mfa`, `#privacy`, and `#complete` are only rendered after the corresponding successful workflow transitions. On invalid direct navigation, return the user to the appropriate earlier screen and do not display completion language unless `/api/privacy` has succeeded."]}
```

## PARSED_TASKS
- Change /api/verify rate limiting to use an IP-based key that is not session-specific, or combine independent IP and session limits so creating a new session cannot reset the network-level verification attempt budget.
- Enforce verifiedFlowExpiresAt in /api/mfa; when expired, clear the recovery flow and return a clear error requiring a new recovery request. Ensure subsequent state-dependent recovery endpoints use consistent expiration handling.
- Add client-side route guards so #reset, #mfa, #privacy, and #complete are only rendered after the corresponding successful workflow transitions. On invalid direct navigation, return the user to the appropriate earlier screen and do not display completion language unless /api/privacy has succeeded.