# TASKER REPORT — Iteration 2 · Step 4

## SUMMARY
- Raw tasks from Tasker: 7
- Effective task_list after retention: 7
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Replace the hard-coded plaintext initial password with a precomputed Argon2id hash or securely supplied runtime secret; no plaintext password may remain in app.ts.","Add a server-side expiration timestamp to each session; session lookup must reject and delete expired records and issue a replacement cookie when a new session is created.","Add a read-only authenticated session-status API endpoint that returns only the current session’s authorized workflow state.","Use server-verified session status to prevent unauthenticated visitors from rendering the /privacy screen.","Render /confirmed only when the current server-side session has privacyAccepted === true; otherwise route the visitor to the appropriate recovery or login screen.","Require and verify MFA or SSO during normal /api/login authentication, with throttling and browser-console-only mock delivery of the deterministic academic code.","Correct the malformed CSS box-shadow declaration so it is valid CSS."]}
```

## PARSED_TASKS
- Replace the hard-coded plaintext initial password with a precomputed Argon2id hash or securely supplied runtime secret; no plaintext password may remain in app.ts.
- Add a server-side expiration timestamp to each session; session lookup must reject and delete expired records and issue a replacement cookie when a new session is created.
- Add a read-only authenticated session-status API endpoint that returns only the current session’s authorized workflow state.
- Use server-verified session status to prevent unauthenticated visitors from rendering the /privacy screen.
- Render /confirmed only when the current server-side session has privacyAccepted === true; otherwise route the visitor to the appropriate recovery or login screen.
- Require and verify MFA or SSO during normal /api/login authentication, with throttling and browser-console-only mock delivery of the deterministic academic code.
- Correct the malformed CSS box-shadow declaration so it is valid CSS.