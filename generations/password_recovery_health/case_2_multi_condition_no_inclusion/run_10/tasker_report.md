# TASKER REPORT — Iteration 2 · Step 4

## SUMMARY
- Raw tasks from Tasker: 4
- Effective task_list after retention: 4
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Implement a bounded server-side rate limiter keyed by trusted client IP address and action, with expiry and cleanup so limits cannot be reset by creating a new session.","Apply the IP/action rate limiter to recovery-token issuance, reset-token verification, password-change submissions, and MFA verification; reject requests exceeding each action's configured limit.","Update the privacy form request to send an explicit boolean acceptance field derived from the checkbox state.","Require `accepted === true` on the server before recording privacy acceptance; otherwise return a validation error without changing the recovery stage."]}
```

## PARSED_TASKS
- Implement a bounded server-side rate limiter keyed by trusted client IP address and action, with expiry and cleanup so limits cannot be reset by creating a new session.
- Apply the IP/action rate limiter to recovery-token issuance, reset-token verification, password-change submissions, and MFA verification; reject requests exceeding each action's configured limit.
- Update the privacy form request to send an explicit boolean acceptance field derived from the checkbox state.
- Require accepted === true on the server before recording privacy acceptance; otherwise return a validation error without changing the recovery stage.