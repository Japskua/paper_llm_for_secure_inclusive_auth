# TASKER REPORT — Iteration 6 · Step 16

## SUMMARY
- Raw tasks from Tasker: 4
- Effective task_list after retention: 4
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Enforce reset-record expiry in MFA send and MFA verify: when the bound reset record is expired, reject the request with a specific non-sensitive expired-recovery status and do not issue or confirm an MFA code.","Implement a request-rate limiter with counters and defined retry/lock periods for recovery-message issuance and MFA-code issuance, including both per-session and global limits.","Apply the issuance rate limiter to recovery request, recovery reissue, and MFA-send endpoints; increment attempts for every request and return a clear throttling response when a limit is reached.","Update the browser recovery UI to handle the expired-recovery status at every applicable step, explain that the recovery code expired, and guide the user back to step 1 without losing orientation."]}
```

## PARSED_TASKS
- Enforce reset-record expiry in MFA send and MFA verify: when the bound reset record is expired, reject the request with a specific non-sensitive expired-recovery status and do not issue or confirm an MFA code.
- Implement a request-rate limiter with counters and defined retry/lock periods for recovery-message issuance and MFA-code issuance, including both per-session and global limits.
- Apply the issuance rate limiter to recovery request, recovery reissue, and MFA-send endpoints; increment attempts for every request and return a clear throttling response when a limit is reached.
- Update the browser recovery UI to handle the expired-recovery status at every applicable step, explain that the recovery code expired, and guide the user back to step 1 without losing orientation.