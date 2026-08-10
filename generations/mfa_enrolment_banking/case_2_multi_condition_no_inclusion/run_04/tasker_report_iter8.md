# TASKER REPORT — Iteration 8 · Step 22

## SUMMARY
- Raw tasks from Tasker: 4
- Effective task_list after retention: 4
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Introduce an explicit test-only mode that is impossible to enable in production and documents its purpose; only in that mode expose deterministic mock identity and authenticator values needed to complete the simulated flow.","Ensure the normal non-test flow has a usable internal simulated identity-delivery path without logging or exposing identity/authenticator OTP values in browser or server logs; keep production verification values unique, time-bound, session-bound, and single-use.","In explicit test-only mode, log each newly generated recovery-code set to the browser console and return it once for the existing recovery-code UI; do not log recovery codes outside that mode.","Store identity-verification failed-attempt counts and lockout expiry in server-side account or identity-level state rather than the transient session, so starting a new sign-in session cannot bypass rate limits or lockout."]}
```

## PARSED_TASKS
- Introduce an explicit test-only mode that is impossible to enable in production and documents its purpose; only in that mode expose deterministic mock identity and authenticator values needed to complete the simulated flow.
- Ensure the normal non-test flow has a usable internal simulated identity-delivery path without logging or exposing identity/authenticator OTP values in browser or server logs; keep production verification values unique, time-bound, session-bound, and single-use.
- In explicit test-only mode, log each newly generated recovery-code set to the browser console and return it once for the existing recovery-code UI; do not log recovery codes outside that mode.
- Store identity-verification failed-attempt counts and lockout expiry in server-side account or identity-level state rather than the transient session, so starting a new sign-in session cannot bypass rate limits or lockout.