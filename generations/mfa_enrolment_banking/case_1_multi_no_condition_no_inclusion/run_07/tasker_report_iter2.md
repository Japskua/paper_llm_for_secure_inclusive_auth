# TASKER REPORT — Iteration 2 · Step 4

## SUMMARY
- Raw tasks from Tasker: 6
- Effective task_list after retention: 6
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["On successful `/api/login`, parse and delete any existing `bank_session` token before creating and issuing the new session token.","Add per-account or per-session recovery-code redemption failure tracking with a bounded attempt count and temporary lockout; return the same generic invalid-code response during lockout to avoid information leakage.","Require `auth.account.mfaEnabled` in `/api/mfa/recovery/redeem`, returning a generic forbidden/error response if MFA is not enabled.","Return enrolment state from `/api/me`, including at minimum `mfaEnabled`, `identityConfirmed`, and whether recovery codes exist, and enforce these server-confirmed states in `route()` before rendering `provision`, `verify`, `recovery`, or `complete`.","Remove the recovery page’s “Skip for now” link, and permit navigation to `#complete` only after recovery codes have been generated and the user has explicitly confirmed they saved them.","Make `completePage()` verify current server enrolment state before rendering “MFA is active”; otherwise route the user to the applicable incomplete enrolment step."]}
```

## PARSED_TASKS
- On successful /api/login, parse and delete any existing `bank_session` token before creating and issuing the new session token.
- Add per-account or per-session recovery-code redemption failure tracking with a bounded attempt count and temporary lockout; return the same generic invalid-code response during lockout to avoid information leakage.
- Require auth.account.mfaEnabled in /api/mfa/recovery/redeem, returning a generic forbidden/error response if MFA is not enabled.
- Return enrolment state from /api/me, including at minimum mfaEnabled, identityConfirmed, and whether recovery codes exist, and enforce these server-confirmed states in route() before rendering provision, verify, recovery, or complete.
- Remove the recovery page’s “Skip for now” link, and permit navigation to #complete only after recovery codes have been generated and the user has explicitly confirmed they saved them.
- Make completePage() verify current server enrolment state before rendering “MFA is active”; otherwise route the user to the applicable incomplete enrolment step.