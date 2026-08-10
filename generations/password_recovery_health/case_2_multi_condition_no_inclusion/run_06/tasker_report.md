# TASKER REPORT — Iteration 2 · Step 4

## SUMMARY
- Raw tasks from Tasker: 6
- Effective task_list after retention: 6
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Correct the recovery email regex to `/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/` and remove `acceptedFormat` from recovery responses so all recovery initiation responses are generic.","Add a server-authoritative recovery-status endpoint that exposes only the current session’s permitted recovery stage without disclosing private account data.","Before rendering `#mfa`, `#reset`, `#privacy`, or `#confirmation`, retrieve the server-authoritative status and redirect users to the earliest permitted stage when prerequisites are incomplete.","Require the server-authoritative completion state, including password reset and privacy acceptance for the owned recovery, before rendering any completion confirmation message.","Implement bounded client/IP-based rate limits that persist independently of sessions and recovery records, and apply them alongside existing limits to recovery initiation and token/MFA/password verification attempts.","Enforce bcrypt-compatible password input length server-side by rejecting passwords whose UTF-8 encoded length exceeds 72 bytes, and align the client-side policy feedback with this limit."]}
```

## PARSED_TASKS
- Correct the recovery email regex to /^[^\s@]+@[^\s@]+\.[^\s@]+$/ and remove acceptedFormat from recovery responses so all recovery initiation responses are generic.
- Add a server-authoritative recovery-status endpoint that exposes only the current session’s permitted recovery stage without disclosing private account data.
- Before rendering #mfa, #reset, #privacy, or #confirmation, retrieve the server-authoritative status and redirect users to the earliest permitted stage when prerequisites are incomplete.
- Require the server-authoritative completion state, including password reset and privacy acceptance for the owned recovery, before rendering any completion confirmation message.
- Implement bounded client/IP-based rate limits that persist independently of sessions and recovery records, and apply them alongside existing limits to recovery initiation and token/MFA/password verification attempts.
- Enforce bcrypt-compatible password input length server-side by rejecting passwords whose UTF-8 encoded length exceeds 72 bytes, and align the client-side policy feedback with this limit.