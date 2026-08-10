# TASKER REPORT — Iteration 3 · Step 7

## SUMMARY
- Raw tasks from Tasker: 4
- Effective task_list after retention: 4
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Add created-at and server-side expiry timestamps to each session, and make getSession reject and delete expired session IDs regardless of cookie state.","Remove expired sessions opportunistically during request handling so the in-memory session store does not retain expired entries.","Add shared server-side failed-attempt tracking keyed by a safe normalized account/identifier and client source IP, rather than storing attempt counts only in a session.","Enforce temporary lockouts or escalating delays from the shared tracker for failed recovery verification, MFA, password-change, and login attempts, including requests made with new sessions."]}
```

## PARSED_TASKS
- Add created-at and server-side expiry timestamps to each session, and make getSession reject and delete expired session IDs regardless of cookie state.
- Remove expired sessions opportunistically during request handling so the in-memory session store does not retain expired entries.
- Add shared server-side failed-attempt tracking keyed by a safe normalized account/identifier and client source IP, rather than storing attempt counts only in a session.
- Enforce temporary lockouts or escalating delays from the shared tracker for failed recovery verification, MFA, password-change, and login attempts, including requests made with new sessions.