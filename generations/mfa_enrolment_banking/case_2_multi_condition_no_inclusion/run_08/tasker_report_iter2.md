# TASKER REPORT — Iteration 2 · Step 4

## SUMMARY
- Raw tasks from Tasker: 3
- Effective task_list after retention: 3
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Split authenticated-account authorization from identity-verified MFA authorization. Add a helper that requires only a valid authenticated session and session-owned account, then use it for /api/identity/send and /api/identity/verify; retain the identity-verified requirement for MFA provisioning, MFA verification, recovery-code operations, and settings.","Implement server-side login throttling/lockout that cannot be reset by creating a new session. Track failed sign-in attempts and lock expiry using an account-scoped or equivalent server-side rate-limit key, while preserving generic responses to avoid account enumeration.","Implement account-scoped identity-verification attempt tracking and lockout. Failed identity-code attempts must remain locked across new sessions/sign-ins until the lock period expires, and successful identity verification should reset the account-level identity failure counter."]}
```

## PARSED_TASKS
- Split authenticated-account authorization from identity-verified MFA authorization. Add a helper that requires only a valid authenticated session and session-owned account, then use it for /api/identity/send and /api/identity/verify; retain the identity-verified requirement for MFA provisioning, MFA verification, recovery-code operations, and settings.
- Implement server-side login throttling/lockout that cannot be reset by creating a new session. Track failed sign-in attempts and lock expiry using an account-scoped or equivalent server-side rate-limit key, while preserving generic responses to avoid account enumeration.
- Implement account-scoped identity-verification attempt tracking and lockout. Failed identity-code attempts must remain locked across new sessions/sign-ins until the lock period expires, and successful identity verification should reset the account-level identity failure counter.