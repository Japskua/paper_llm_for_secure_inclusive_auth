# TASKER REPORT — Iteration 4 · Step 10

## SUMMARY
- Raw tasks from Tasker: 6
- Effective task_list after retention: 6
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Move authenticator secret creation to a CSRF-validated POST endpoint; ensure any GET provisioning endpoint is read-only and never writes account state.","Preserve identity-verification failure counts and lockout expiry across code re-requests, and reject code-send requests while the identity verification lockout is active.","Rate-limit identity-code resend requests server-side and return a clear message stating when the user may request another code.","Use real elapsed time for code expiry, lockout expiry, and session idle/absolute expiry in every mode; retain deterministic mock values without freezing clocks.","Make the simulated identity code available through browser console logging by default so the runnable academic flow can complete, while keeping any production-specific delivery behavior explicitly separated.","After an identity code has been sent, render Check code as the only primary action and render Send another code as a clearly secondary control."]}
```

## PARSED_TASKS
- Move authenticator secret creation to a CSRF-validated POST endpoint; ensure any GET provisioning endpoint is read-only and never writes account state.
- Preserve identity-verification failure counts and lockout expiry across code re-requests, and reject code-send requests while the identity verification lockout is active.
- Rate-limit identity-code resend requests server-side and return a clear message stating when the user may request another code.
- Use real elapsed time for code expiry, lockout expiry, and session idle/absolute expiry in every mode; retain deterministic mock values without freezing clocks.
- Make the simulated identity code available through browser console logging by default so the runnable academic flow can complete, while keeping any production-specific delivery behavior explicitly separated.
- After an identity code has been sent, render Check code as the only primary action and render Send another code as a clearly secondary control.