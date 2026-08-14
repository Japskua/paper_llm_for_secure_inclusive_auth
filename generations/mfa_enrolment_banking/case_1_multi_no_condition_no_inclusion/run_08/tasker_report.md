# TASKER REPORT — Iteration 5 · Step 13

## SUMMARY
- Raw tasks from Tasker: 4
- Effective task_list after retention: 4
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Load current recovery codes in the recovery screen. Update recovery() to call GET /api/mfa/recovery before rendering the code list, populate delivery.codes from the response, and show a generic UI error if loading fails.","Refresh recovery-code data from GET /api/mfa/recovery after a recovery code is consumed or recovery codes are regenerated before rendering the updated list.","Route users by server-side MFA status immediately after successful sign-in. After updating the CSRF token, request /api/mfa/status and route to confirmed() if mfaEnabled, setup() if identityConfirmed only, or identity() otherwise.","Prevent ordinary authenticated users with MFA already enabled from re-entering setup and replacing the existing authenticator secret."]}
```

## PARSED_TASKS
- Load current recovery codes in the recovery screen. Update recovery() to call GET /api/mfa/recovery before rendering the code list, populate delivery.codes from the response, and show a generic UI error if loading fails.
- Refresh recovery-code data from GET /api/mfa/recovery after a recovery code is consumed or recovery codes are regenerated before rendering the updated list.
- Route users by server-side MFA status immediately after successful sign-in. After updating the CSRF token, request /api/mfa/status and route to confirmed() if mfaEnabled, setup() if identityConfirmed only, or identity() otherwise.
- Prevent ordinary authenticated users with MFA already enabled from re-entering setup and replacing the existing authenticator secret.