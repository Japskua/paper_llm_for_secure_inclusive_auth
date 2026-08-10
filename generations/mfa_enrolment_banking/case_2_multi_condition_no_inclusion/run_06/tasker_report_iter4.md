# TASKER REPORT — Iteration 4 · Step 10

## SUMMARY
- Raw tasks from Tasker: 4
- Effective task_list after retention: 4
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Issue a cryptographically random, short-lived pre-authentication CSRF token bound to a server-side pre-auth context when the sign-in page is loaded, and submit it with the sign-in form.","Require POST /api/login to validate the submitted pre-authentication CSRF token and its bound context before processing credentials, rotating a session, or issuing a session cookie.","Invalidate or rotate the pre-authentication CSRF token and its server-side context after a successful login so it cannot be reused.","Reject cross-site POST /api/login requests using server-side Origin and Fetch Metadata validation as defense in depth."]}
```

## PARSED_TASKS
- Issue a cryptographically random, short-lived pre-authentication CSRF token bound to a server-side pre-auth context when the sign-in page is loaded, and submit it with the sign-in form.
- Require POST /api/login to validate the submitted pre-authentication CSRF token and its bound context before processing credentials, rotating a session, or issuing a session cookie.
- Invalidate or rotate the pre-authentication CSRF token and its server-side context after a successful login so it cannot be reused.
- Reject cross-site POST /api/login requests using server-side Origin and Fetch Metadata validation as defense in depth.