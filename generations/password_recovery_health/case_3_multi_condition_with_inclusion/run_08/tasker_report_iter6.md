# TASKER REPORT — Iteration 6 · Step 16

## SUMMARY
- Raw tasks from Tasker: 6
- Effective task_list after retention: 6
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Make `/api/reset-validate` return a non-success status and no verified reset state for malformed, expired, used, unauthorized, or invalid recovery codes; return success only after establishing a valid server-side verification state.","Change the browser recovery-code handler to move to password creation only when the reset-validation response explicitly confirms server-side verification, and display the returned error without advancing otherwise.","Require a valid, server-side verified reset state in `/api/reset-complete`; make the browser show “Password saved” only after a successful completion response and retain the password step with clear error feedback on failure.","After recovery is initiated, simulate trusted delivery by logging the deterministic delivery authorization code to the browser console while withholding the random reset token until correct delivery authorization succeeds.","Stop trusting client-provided `X-Forwarded-For` headers for request identity unless a configured trusted reverse proxy is actually enforced.","Enforce login and recovery-delivery attempt limits using server-controlled state keyed to the protected account/recovery context and a trustworthy request identity so new sessions or spoofed headers cannot reset the limit."]}
```

## PARSED_TASKS
- Make /api/reset-validate return a non-success status and no verified reset state for malformed, expired, used, unauthorized, or invalid recovery codes; return success only after establishing a valid server-side verification state.
- Change the browser recovery-code handler to move to password creation only when the reset-validation response explicitly confirms server-side verification, and display the returned error without advancing otherwise.
- Require a valid, server-side verified reset state in /api/reset-complete; make the browser show “Password saved” only after a successful completion response and retain the password step with clear error feedback on failure.
- After recovery is initiated, simulate trusted delivery by logging the deterministic delivery authorization code to the browser console while withholding the random reset token until correct delivery authorization succeeds.
- Stop trusting client-provided X-Forwarded-For headers for request identity unless a configured trusted reverse proxy is actually enforced.
- Enforce login and recovery-delivery attempt limits using server-controlled state keyed to the protected account/recovery context and a trustworthy request identity so new sessions or spoofed headers cannot reset the limit.