# TASKER REPORT — Iteration 6 · Step 16

## SUMMARY
- Raw tasks from Tasker: 3
- Effective task_list after retention: 3
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Add server-side failed-attempt tracking and a lockout/rate-limit policy for POST /api/auth/owner. Return the same non-enumerating credential error for failures and a clear temporary-lockout message after the configured threshold.","Allow POST /api/mfa/recovery/verify for a session that has completed first-factor identity verification but is not yet MFA-verified. On successful one-time recovery-code verification, consume the code and mark that session MFA-verified.","Handle invalid JSON, unsupported content types, malformed content lengths, and oversized request bodies explicitly on authenticated API routes. Return HTTP 400 or 413 with plain-language, non-sensitive validation messages instead of a generic HTTP 500 response."]}
```

## PARSED_TASKS
- Add server-side failed-attempt tracking and a lockout/rate-limit policy for POST /api/auth/owner. Return the same non-enumerating credential error for failures and a clear temporary-lockout message after the configured threshold.
- Allow POST /api/mfa/recovery/verify for a session that has completed first-factor identity verification but is not yet MFA-verified. On successful one-time recovery-code verification, consume the code and mark that session MFA-verified.
- Handle invalid JSON, unsupported content types, malformed content lengths, and oversized request bodies explicitly on authenticated API routes. Return HTTP 400 or 413 with plain-language, non-sensitive validation messages instead of a generic HTTP 500 response.