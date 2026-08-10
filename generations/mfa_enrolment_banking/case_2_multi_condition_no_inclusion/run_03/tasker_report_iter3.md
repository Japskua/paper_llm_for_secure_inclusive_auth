# TASKER REPORT — Iteration 3 · Step 7

## SUMMARY
- Raw tasks from Tasker: 4
- Effective task_list after retention: 4
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Normalize recovery codes identically before both storage and verification. For example, hash normalizeBackup(code) during generation, or preserve the hyphen during verification; add a test that a newly displayed recovery code succeeds once and fails on its second use.","Preserve and enforce TOTP lockout state when /api/mfa/begin is called. Do not clear totpFailures or totpLockedUntil merely because a new setup secret is generated; clear failure state only after a successful verification or after the lock period has elapsed under controlled logic.","Move identity-verification failure and lockout tracking from the rotating session into server-side state keyed to a normalized identity attempt/account-safe identifier, so a new sign-in or new session cannot bypass the lockout. Keep responses generic to avoid account enumeration.","Update the successful /api/auth/identity client handler to route with r.mfaEnabled ? status() : setup() rather than always invoking setup()."]}
```

## PARSED_TASKS
- Normalize recovery codes identically before both storage and verification. For example, hash normalizeBackup(code) during generation, or preserve the hyphen during verification; add a test that a newly displayed recovery code succeeds once and fails on its second use.
- Preserve and enforce TOTP lockout state when /api/mfa/begin is called. Do not clear totpFailures or totpLockedUntil merely because a new setup secret is generated; clear failure state only after a successful verification or after the lock period has elapsed under controlled logic.
- Move identity-verification failure and lockout tracking from the rotating session into server-side state keyed to a normalized identity attempt/account-safe identifier, so a new sign-in or new session cannot bypass the lockout. Keep responses generic to avoid account enumeration.
- Update the successful /api/auth/identity client handler to route with r.mfaEnabled ? status() : setup() rather than always invoking setup().