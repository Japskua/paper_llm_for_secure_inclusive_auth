# TASKER REPORT — Iteration 2 · Step 4

## SUMMARY
- Raw tasks from Tasker: 4
- Effective task_list after retention: 4
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Require /api/signin to authenticate submitted credentials against a server-side account fixture before creating any identity-verification session; return a generic failure for invalid credentials and bind a successful session only to that verified account.","Count every failed identity, MFA-activation, and TOTP-check verification attempt after session and lock checks—including malformed OTP values and mismatched valid-format manual secrets—toward the configured lockout threshold.","Add browser console.log instrumentation for authenticator provisioning that reports the deterministic evaluation secret or provisioning simulation without server-side secret logging.","Add browser console.log instrumentation for authenticator verification outcomes, and document the deterministic mock-value behavior used for evaluation."]}
```

## PARSED_TASKS
- Require /api/signin to authenticate submitted credentials against a server-side account fixture before creating any identity-verification session; return a generic failure for invalid credentials and bind a successful session only to that verified account.
- Count every failed identity, MFA-activation, and TOTP-check verification attempt after session and lock checks—including malformed OTP values and mismatched valid-format manual secrets—toward the configured lockout threshold.
- Add browser console.log instrumentation for authenticator provisioning that reports the deterministic evaluation secret or provisioning simulation without server-side secret logging.
- Add browser console.log instrumentation for authenticator verification outcomes, and document the deterministic mock-value behavior used for evaluation.