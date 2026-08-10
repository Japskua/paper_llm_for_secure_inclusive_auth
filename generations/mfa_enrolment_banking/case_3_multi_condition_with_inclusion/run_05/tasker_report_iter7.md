# TASKER REPORT — Iteration 7 · Step 19

## SUMMARY
- Raw tasks from Tasker: 4
- Effective task_list after retention: 4
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Update `/api/authenticator/activate` to reject every submission while `account.auth.locked` is still in the future, before validating the OTP, and return a clear lockout response.","Ensure `/api/provision` preserves authenticator verification attempts and an active lockout instead of replacing `account.auth`; reject reprovisioning until an active setup lockout expires.","Add an authenticated, CSRF-protected endpoint that returns the current simulated OTP for the pending provisioning secret, and add a setup-screen action that requests it and logs/displays the current test code without restarting provisioning.","Add accessible show/hide controls for the setup secret and recovery-code list, with clear state labels and unchanged copy functionality."]}
```

## PARSED_TASKS
- Update /api/authenticator/activate to reject every submission while account.auth.locked is still in the future, before validating the OTP, and return a clear lockout response.
- Ensure /api/provision preserves authenticator verification attempts and an active lockout instead of replacing account.auth; reject reprovisioning until an active setup lockout expires.
- Add an authenticated, CSRF-protected endpoint that returns the current simulated OTP for the pending provisioning secret, and add a setup-screen action that requests it and logs/displays the current test code without restarting provisioning.
- Add accessible show/hide controls for the setup secret and recovery-code list, with clear state labels and unchanged copy functionality.