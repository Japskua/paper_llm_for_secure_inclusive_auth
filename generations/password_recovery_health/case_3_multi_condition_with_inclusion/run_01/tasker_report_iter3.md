# TASKER REPORT — Iteration 3 · Step 7

## SUMMARY
- Raw tasks from Tasker: 6
- Effective task_list after retention: 6
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Make reset-request responses, status messaging, and UI behavior indistinguishable for registered and unregistered normalized email addresses; provide the same safe simulated delivery result without exposing a real reset token for account enumeration.","Add server-side rate limiting for reset requests using normalized email and client IP or an equivalent abuse-control key, returning a bounded retry window after the limit is reached.","Replace session-only login and reset-code verification throttles with server-side limits keyed to credentials/token and client IP so creating a new session cannot bypass them; increment and enforce any token-level failure counter or remove it.","On successful reset-token verification, atomically consume the token and issue a separate random, short-lived, session-bound password-reset grant required by the password-change endpoint.","When the app loads with a valid ?token= recovery URL, always show the Verify step and prefill the manual recovery-code field, including for a newly created session.","Add a separate MFA item to the visible progress indicator and mark it as the active step while MFA verification is shown."]}
```

## PARSED_TASKS
- Make reset-request responses, status messaging, and UI behavior indistinguishable for registered and unregistered normalized email addresses; provide the same safe simulated delivery result without exposing a real reset token for account enumeration.
- Add server-side rate limiting for reset requests using normalized email and client IP or an equivalent abuse-control key, returning a bounded retry window after the limit is reached.
- Replace session-only login and reset-code verification throttles with server-side limits keyed to credentials/token and client IP so creating a new session cannot bypass them; increment and enforce any token-level failure counter or remove it.
- On successful reset-token verification, atomically consume the token and issue a separate random, short-lived, session-bound password-reset grant required by the password-change endpoint.
- When the app loads with a valid ?token= recovery URL, always show the Verify step and prefill the manual recovery-code field, including for a newly created session.
- Add a separate MFA item to the visible progress indicator and mark it as the active step while MFA verification is shown.