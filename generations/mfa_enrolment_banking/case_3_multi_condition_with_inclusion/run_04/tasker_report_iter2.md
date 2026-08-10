# TASKER REPORT — Iteration 2 · Step 4

## SUMMARY
- Raw tasks from Tasker: 5
- Effective task_list after retention: 5
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Update Origin validation and CORS headers to allow only the actual trusted application origin, including the HTTPS port (for example, https://localhost:3000), so legitimate same-origin state-changing requests succeed.","Preserve a valid existing session when serving or refreshing the SPA; issue and set a new anonymous session cookie only when the request has no valid session.","Add an entirely local, inline QR-code provisioning option for the authenticator URI alongside the manual secret, URI display, and copy controls.","Store an expiry timestamp for each pending authenticator OTP and reject authenticator verification after expiry with a clear retry/new-setup path.","Track failed authenticator OTP verification attempts and enforce a temporary lockout/rate limit after repeated failures, returning a specific user-facing error and allowing a new setup attempt."]}
```

## PARSED_TASKS
- Update Origin validation and CORS headers to allow only the actual trusted application origin, including the HTTPS port (for example, https://localhost:3000), so legitimate same-origin state-changing requests succeed.
- Preserve a valid existing session when serving or refreshing the SPA; issue and set a new anonymous session cookie only when the request has no valid session.
- Add an entirely local, inline QR-code provisioning option for the authenticator URI alongside the manual secret, URI display, and copy controls.
- Store an expiry timestamp for each pending authenticator OTP and reject authenticator verification after expiry with a clear retry/new-setup path.
- Track failed authenticator OTP verification attempts and enforce a temporary lockout/rate limit after repeated failures, returning a specific user-facing error and allowing a new setup attempt.