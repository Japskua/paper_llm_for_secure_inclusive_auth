# TASKER REPORT — Iteration 2 · Step 4

## SUMMARY
- Raw tasks from Tasker: 9
- Effective task_list after retention: 9
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Replace the decorative QR canvas with a standards-compliant QR encoder whose payload is exactly the pending provisioning URI, and provide accessible text explaining that it configures an authenticator app.","Verify authenticator entries as six-digit TOTP values derived from the pending provisioning secret using HMAC-SHA1 and an accepted time window; any deterministic test code must be valid for that same secret.","Bind authentication to a server-side mock user/account record keyed by the authenticated identity, so an authenticated user can access only that account's MFA data and cannot obtain another account's state through a submitted identifier.","Store MFA enrolment status and related MFA state on the account record, and derive each newly created session's MFA status from that account-level state.","Require strict trusted-origin validation for every state-changing request, including authentication, and add a pre-login CSRF token or equivalent same-origin login protection.","Add server-side recovery-code failed-attempt tracking, rate limiting, and lockout with clear retry guidance.","Keep authenticator setup failure and lockout state at account scope or otherwise preserve it across setup restarts, so a restart cannot bypass the failed-attempt limit.","Generate high-entropy recovery codes and protect stored recovery-code verifiers with a unique salt and a slow password-hashing/KDF mechanism.","Remove the visible in-page credential log and prevent normal browser/server logs from exposing provisioning secrets, OTPs, or recovery codes; if assessment-only mock disclosure is retained, isolate it behind an explicit test-only path that is absent from the normal UI."]}
```

## PARSED_TASKS
- Replace the decorative QR canvas with a standards-compliant QR encoder whose payload is exactly the pending provisioning URI, and provide accessible text explaining that it configures an authenticator app.
- Verify authenticator entries as six-digit TOTP values derived from the pending provisioning secret using HMAC-SHA1 and an accepted time window; any deterministic test code must be valid for that same secret.
- Bind authentication to a server-side mock user/account record keyed by the authenticated identity, so an authenticated user can access only that account's MFA data and cannot obtain another account's state through a submitted identifier.
- Store MFA enrolment status and related MFA state on the account record, and derive each newly created session's MFA status from that account-level state.
- Require strict trusted-origin validation for every state-changing request, including authentication, and add a pre-login CSRF token or equivalent same-origin login protection.
- Add server-side recovery-code failed-attempt tracking, rate limiting, and lockout with clear retry guidance.
- Keep authenticator setup failure and lockout state at account scope or otherwise preserve it across setup restarts, so a restart cannot bypass the failed-attempt limit.
- Generate high-entropy recovery codes and protect stored recovery-code verifiers with a unique salt and a slow password-hashing/KDF mechanism.
- Remove the visible in-page credential log and prevent normal browser/server logs from exposing provisioning secrets, OTPs, or recovery codes; if assessment-only mock disclosure is retained, isolate it behind an explicit test-only path that is absent from the normal UI.