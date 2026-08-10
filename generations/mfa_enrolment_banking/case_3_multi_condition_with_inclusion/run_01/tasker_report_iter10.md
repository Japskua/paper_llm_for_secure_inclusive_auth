# TASKER REPORT — Iteration 10 · Step 28

## SUMMARY
- Raw tasks from Tasker: 3
- Effective task_list after retention: 3
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Remove OTP failure-counter and lockout resets from `/api/provision`; preserve OTP lockout state until the configured lockout period expires or until a successful OTP verification occurs.","Introduce a separate pending-enrolment secret state so `/api/provision` creates or replaces only a pending secret, and promote it to the active MFA secret only after `/api/verify-otp` succeeds.","When MFA is already enabled, require an explicit authenticated MFA-reset/re-enrolment flow that preserves the currently active authenticator until the replacement authenticator has been successfully verified."]}
```

## PARSED_TASKS
- Remove OTP failure-counter and lockout resets from /api/provision; preserve OTP lockout state until the configured lockout period expires or until a successful OTP verification occurs.
- Introduce a separate pending-enrolment secret state so /api/provision creates or replaces only a pending secret, and promote it to the active MFA secret only after /api/verify-otp succeeds.
- When MFA is already enabled, require an explicit authenticated MFA-reset/re-enrolment flow that preserves the currently active authenticator until the replacement authenticator has been successfully verified.