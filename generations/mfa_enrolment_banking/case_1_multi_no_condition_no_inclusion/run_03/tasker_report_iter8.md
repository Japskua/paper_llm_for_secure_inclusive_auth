# TASKER REPORT — Iteration 8 · Step 22

## SUMMARY
- Raw tasks from Tasker: 4
- Effective task_list after retention: 4
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Replace the regex-based arbitrary-port trusted-origin check with an explicit allow-list containing the configured application origin `https://localhost:${port}` and only intentionally supported loopback aliases for that same port.","Return `Access-Control-Allow-Origin` and credentialed CORS headers only when the request Origin exactly matches an explicit allow-list entry.","Require a present, exact allow-listed Origin plus the valid per-session CSRF token for every state-changing API request; reject requests with a missing Origin.","Document the configured trusted origins and ensure the client-served origin for the active `PORT` is included in the explicit allow-list."]}
```

## PARSED_TASKS
- Replace the regex-based arbitrary-port trusted-origin check with an explicit allow-list containing the configured application origin https://localhost:${port} and only intentionally supported loopback aliases for that same port.
- Return Access-Control-Allow-Origin and credentialed CORS headers only when the request Origin exactly matches an explicit allow-list entry.
- Require a present, exact allow-listed Origin plus the valid per-session CSRF token for every state-changing API request; reject requests with a missing Origin.
- Document the configured trusted origins and ensure the client-served origin for the active PORT is included in the explicit allow-list.