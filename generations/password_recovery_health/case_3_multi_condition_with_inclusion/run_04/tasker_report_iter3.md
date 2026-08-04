# TASKER REPORT — Iteration 3 · Step 7

## SUMMARY
- Raw tasks from Tasker: 5
- Effective task_list after retention: 5
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Add server-side failed-attempt tracking and temporary lockouts for recovery channel confirmation and reset-token verification, with bounded attempts and generic non-enumerating responses.","Return a distinct response for an incorrect recovery token while the recovery session and token remain valid; reserve unavailable-state responses for expired, used, or invalid recovery state.","Preserve browser recovery progress and the stored token after an incorrect manual recovery-code entry, allowing the user to correct and resubmit it.","Provide a CSRF-protected way to abandon an active recovery attempt and return the session to anonymous state, with a visible recovery-stage action to start again.","When MFA attempts are exhausted, invalidate the MFA challenge, transition to a recoverable state, and show a clear message with an action to sign in again or restart password recovery."]}
```

## PARSED_TASKS
- Add server-side failed-attempt tracking and temporary lockouts for recovery channel confirmation and reset-token verification, with bounded attempts and generic non-enumerating responses.
- Return a distinct response for an incorrect recovery token while the recovery session and token remain valid; reserve unavailable-state responses for expired, used, or invalid recovery state.
- Preserve browser recovery progress and the stored token after an incorrect manual recovery-code entry, allowing the user to correct and resubmit it.
- Provide a CSRF-protected way to abandon an active recovery attempt and return the session to anonymous state, with a visible recovery-stage action to start again.
- When MFA attempts are exhausted, invalidate the MFA challenge, transition to a recoverable state, and show a clear message with an action to sign in again or restart password recovery.