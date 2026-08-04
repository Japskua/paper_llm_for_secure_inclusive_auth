# TASKER REPORT — Iteration 3 · Step 7

## SUMMARY
- Raw tasks from Tasker: 4
- Effective task_list after retention: 4
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Allow a valid, unexpired reset token supplied in `?token=` to establish a restricted recovery-verification session in a new browser session, while retaining CSRF validation for all subsequent state-changing requests.","Ensure password-reset authorization is single-use: after a successful password update, consume or clear recovery authorization and reject further password updates until a newly issued token is verified.","Make cookie parsing resilient to malformed percent-encoding by safely handling `decodeURIComponent` failures and ignoring invalid cookie values.","Wrap request handling in a safe error boundary that returns a generic non-debug error response with the required security headers when unexpected server errors occur."]}
```

## PARSED_TASKS
- Allow a valid, unexpired reset token supplied in ?token= to establish a restricted recovery-verification session in a new browser session, while retaining CSRF validation for all subsequent state-changing requests.
- Ensure password-reset authorization is single-use: after a successful password update, consume or clear recovery authorization and reject further password updates until a newly issued token is verified.
- Make cookie parsing resilient to malformed percent-encoding by safely handling decodeURIComponent failures and ignoring invalid cookie values.
- Wrap request handling in a safe error boundary that returns a generic non-debug error response with the required security headers when unexpected server errors occur.