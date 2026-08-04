# TASKER REPORT — Iteration 4 · Step 10

## SUMMARY
- Raw tasks from Tasker: 4
- Effective task_list after retention: 4
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Refactor `/api/reset/verify` to retrieve the session-bound active reset record before comparing the submitted token, enforce verification lockout first, and register a failure for every invalid or malformed submitted token before returning an error.","Add session-backed persistence for non-secret workflow state, including the current stage, paused status, and pending MFA stage; restore the applicable stage after reload without storing passwords or verification codes in browser storage.","Make the pause control save the current workflow state through a CSRF-protected API request, disable or clearly indicate paused interactions as appropriate, and provide accurate saved/resumed feedback.","Replace the “No time limit” wording with clear low-stress guidance that users may proceed at their own pace while recovery and MFA codes expire after 10 minutes for safety and can be requested again."]}
```

## PARSED_TASKS
- Refactor /api/reset/verify to retrieve the session-bound active reset record before comparing the submitted token, enforce verification lockout first, and register a failure for every invalid or malformed submitted token before returning an error.
- Add session-backed persistence for non-secret workflow state, including the current stage, paused status, and pending MFA stage; restore the applicable stage after reload without storing passwords or verification codes in browser storage.
- Make the pause control save the current workflow state through a CSRF-protected API request, disable or clearly indicate paused interactions as appropriate, and provide accurate saved/resumed feedback.
- Replace the “No time limit” wording with clear low-stress guidance that users may proceed at their own pace while recovery and MFA codes expire after 10 minutes for safety and can be requested again.