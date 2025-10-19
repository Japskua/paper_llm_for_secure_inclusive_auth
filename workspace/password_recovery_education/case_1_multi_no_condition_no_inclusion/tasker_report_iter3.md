# TASKER REPORT — Iteration 3 · Step 7

## SUMMARY
- Raw tasks from Tasker: 3
- Effective task_list after retention: 3
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Modify the client logout flow to perform a full page reload after a successful POST /api/logout so the CSRF meta token is refreshed; acceptance: immediately logging in after logout (without manual refresh) must not produce a CSRF error.",
    "Optional hardening (server): Return a fresh CSRF token in the JSON response of POST /api/logout and rotate the session; acceptance: the response body contains a non-empty csrf token string.",
    "Optional hardening (client): If not reloading the page, update the <meta name=\"csrf-token\"> content with the token returned from POST /api/logout; acceptance: subsequent POST requests succeed without CSRF errors without requiring a full reload."
  ]
}
```

## PARSED_TASKS
- Modify the client logout flow to perform a full page reload after a successful POST /api/logout so the CSRF meta token is refreshed; acceptance: immediately logging in after logout (without manual refresh) must not produce a CSRF error.
- Optional hardening (server): Return a fresh CSRF token in the JSON response of POST /api/logout and rotate the session; acceptance: the response body contains a non-empty csrf token string.
- Optional hardening (client): If not reloading the page, update the <meta name="csrf-token"> content with the token returned from POST /api/logout; acceptance: subsequent POST requests succeed without CSRF errors without requiring a full reload.