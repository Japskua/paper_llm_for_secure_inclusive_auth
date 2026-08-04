# TASKER REPORT — Iteration 2 · Step 4

## SUMMARY
- Raw tasks from Tasker: 3
- Effective task_list after retention: 3
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Replace session-only throttling with bounded, expiring server-side rate-limit records that cannot be reset by obtaining a new session. Apply it at minimum to recovery requests, reset-token verification failures, and MFA verification failures, while keeping responses generic and non-enumerating.","Implement a client-side flow-state guard so password, MFA, privacy, appointment, and completion views are reachable only after their required successful API transitions in the current browser flow. Route direct, invalid, or premature hash navigation to the recovery-request view.","Display the completion view only after a successful `/api/request-appointment` response. Direct navigation to `/#complete` must not show an appointment-recorded confirmation."]}
```

## PARSED_TASKS
- Replace session-only throttling with bounded, expiring server-side rate-limit records that cannot be reset by obtaining a new session. Apply it at minimum to recovery requests, reset-token verification failures, and MFA verification failures, while keeping responses generic and non-enumerating.
- Implement a client-side flow-state guard so password, MFA, privacy, appointment, and completion views are reachable only after their required successful API transitions in the current browser flow. Route direct, invalid, or premature hash navigation to the recovery-request view.
- Display the completion view only after a successful /api/request-appointment response. Direct navigation to /#complete must not show an appointment-recorded confirmation.