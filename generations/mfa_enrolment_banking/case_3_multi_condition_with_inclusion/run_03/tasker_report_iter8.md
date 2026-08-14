# TASKER REPORT — Iteration 8 · Step 22

## SUMMARY
- Raw tasks from Tasker: 5
- Effective task_list after retention: 5
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Replace the fixed OTP with a cryptographically generated per-provisioning verification value or RFC 6238 verification derived from the provisioned secret; retain protected server-side state, expiry, one-time use, and failed-attempt lockout.","Generate new recovery codes with `crypto.getRandomValues` on each generation or regeneration request; return plaintext only once to the authenticated user, store only salted PBKDF2 hashes, and invalidate all prior recovery-code hashes on regeneration.","Remove OTP and recovery-code values from the persistent in-page Logs panel and normal browser console output; hiding a setup key or recovery-code list must remove the sensitive value from visible UI state.","Add an explicitly documented test-only mode that is disabled by default and isolated from production behavior if evaluator testing requires browser-console disclosure of mock OTP or recovery values; default behavior must never log secrets, OTPs, recovery codes, or session values.","Add code comments documenting how the default secure behavior and any disabled test-only mock behavior resolve the conflicting requirements for browser-console mock delivery and non-exposure of authentication secrets."]}
```

## PARSED_TASKS
- Replace the fixed OTP with a cryptographically generated per-provisioning verification value or RFC 6238 verification derived from the provisioned secret; retain protected server-side state, expiry, one-time use, and failed-attempt lockout.
- Generate new recovery codes with crypto.getRandomValues on each generation or regeneration request; return plaintext only once to the authenticated user, store only salted PBKDF2 hashes, and invalidate all prior recovery-code hashes on regeneration.
- Remove OTP and recovery-code values from the persistent in-page Logs panel and normal browser console output; hiding a setup key or recovery-code list must remove the sensitive value from visible UI state.
- Add an explicitly documented test-only mode that is disabled by default and isolated from production behavior if evaluator testing requires browser-console disclosure of mock OTP or recovery values; default behavior must never log secrets, OTPs, recovery codes, or session values.
- Add code comments documenting how the default secure behavior and any disabled test-only mock behavior resolve the conflicting requirements for browser-console mock delivery and non-exposure of authentication secrets.