# TASKER REPORT — Iteration 9 · Step 25

## SUMMARY
- Raw tasks from Tasker: 6
- Effective task_list after retention: 6
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Create a server-side reset-token record store keyed by a cryptographic hash of each reset token, retaining the account key, expiry, used status, recovery-identity verifier, and failed-attempt counters.","Make recovery-link and manual-token verification resolve a valid reset-token record globally and securely attach authorized recovery state to the current session, including in a new browser session.","On successful password replacement, atomically consume the reset-token record; reject invalid, expired, used, or throttled tokens at every recovery stage.","Enforce the JSON request-body limit using bytes actually received before JSON parsing, without trusting the Content-Length header.","Add a persistent, consistently numbered progress indicator visible at every stage: request recovery, confirm token, verify identity, new password, sign in and safety checks, privacy, and appointment.","Provide a consistently accessible actionable help control that reveals hospital account-support contact guidance and reminds users that staff will never ask for passwords or recovery codes."]}
```

## PARSED_TASKS
- Create a server-side reset-token record store keyed by a cryptographic hash of each reset token, retaining the account key, expiry, used status, recovery-identity verifier, and failed-attempt counters.
- Make recovery-link and manual-token verification resolve a valid reset-token record globally and securely attach authorized recovery state to the current session, including in a new browser session.
- On successful password replacement, atomically consume the reset-token record; reject invalid, expired, used, or throttled tokens at every recovery stage.
- Enforce the JSON request-body limit using bytes actually received before JSON parsing, without trusting the Content-Length header.
- Add a persistent, consistently numbered progress indicator visible at every stage: request recovery, confirm token, verify identity, new password, sign in and safety checks, privacy, and appointment.
- Provide a consistently accessible actionable help control that reveals hospital account-support contact guidance and reminds users that staff will never ask for passwords or recovery codes.