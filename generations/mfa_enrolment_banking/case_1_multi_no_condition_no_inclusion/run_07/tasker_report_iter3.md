# TASKER REPORT — Iteration 3 · Step 7

## SUMMARY
- Raw tasks from Tasker: 2
- Effective task_list after retention: 2
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Reject supplied account-identifying fields (`userId`, `accountId`, `email`, or equivalent) with a generic 403 on every authenticated account, session, and MFA endpoint, including `/api/me` and `/api/logout`, whether supplied in query parameters or request bodies.","Implement RFC 6238-compatible six-digit TOTP verification by Base32-decoding the manual secret, using a 30-second 8-byte big-endian counter and HOTP dynamic truncation with a documented HMAC algorithm; accept current and previous windows while retaining provisioning expiry, single-use, and failed-attempt lockout protections."]}
```

## PARSED_TASKS
- Reject supplied account-identifying fields (userId, accountId, email, or equivalent) with a generic 403 on every authenticated account, session, and MFA endpoint, including /api/me and /api/logout, whether supplied in query parameters or request bodies.
- Implement RFC 6238-compatible six-digit TOTP verification by Base32-decoding the manual secret, using a 30-second 8-byte big-endian counter and HOTP dynamic truncation with a documented HMAC algorithm; accept current and previous windows while retaining provisioning expiry, single-use, and failed-attempt lockout protections.