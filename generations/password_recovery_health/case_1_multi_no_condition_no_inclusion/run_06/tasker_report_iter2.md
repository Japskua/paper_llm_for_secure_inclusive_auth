# TASKER REPORT — Iteration 2 · Step 4

## SUMMARY
- Raw tasks from Tasker: 3
- Effective task_list after retention: 3
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Make reset-token consumption atomic in `/api/reset/confirm`: reserve the validated verified reset record before awaiting password hashing, reject concurrent reuse, and never restore it in a way that permits reuse if hashing fails.","Replace session-only throttling with shared server-side limits: apply reset request/verification limits to a server-controlled normalized-contact digest and apply login and MFA failures/lockouts at global or account scope so a new session cannot bypass them.","In `/api/login`, reject password values that are not strings or are outside 1–128 characters with the same generic invalid-credentials response, and pass the original validated password unchanged to `Bun.password.verify`."]}
```

## PARSED_TASKS
- Make reset-token consumption atomic in /api/reset/confirm: reserve the validated verified reset record before awaiting password hashing, reject concurrent reuse, and never restore it in a way that permits reuse if hashing fails.
- Replace session-only throttling with shared server-side limits: apply reset request/verification limits to a server-controlled normalized-contact digest and apply login and MFA failures/lockouts at global or account scope so a new session cannot bypass them.
- In /api/login, reject password values that are not strings or are outside 1–128 characters with the same generic invalid-credentials response, and pass the original validated password unchanged to Bun.password.verify.