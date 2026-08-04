# TASKER REPORT — Iteration 5 · Step 13

## SUMMARY
- Raw tasks from Tasker: 3
- Effective task_list after retention: 3
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Add a server-side client-level rate-limit key that cannot be reset by simply creating a new session, such as a carefully normalized client IP address derived only from direct connection metadata; do not trust forwarding headers unless a trusted proxy is explicitly configured.","Apply client-level throttling in addition to existing per-session/per-token limits on `/api/recovery`, `/api/verify-token`, `/api/mfa`, and `/api/login`, returning a generic retry response when blocked.","Add bounded cleanup for client-level rate-limit records so expired throttle entries are removed and client metadata is retained no longer than the applicable throttle window."]}
```

## PARSED_TASKS
- Add a server-side client-level rate-limit key that cannot be reset by simply creating a new session, such as a carefully normalized client IP address derived only from direct connection metadata; do not trust forwarding headers unless a trusted proxy is explicitly configured.
- Apply client-level throttling in addition to existing per-session/per-token limits on /api/recovery, /api/verify-token, /api/mfa, and /api/login, returning a generic retry response when blocked.
- Add bounded cleanup for client-level rate-limit records so expired throttle entries are removed and client metadata is retained no longer than the applicable throttle window.