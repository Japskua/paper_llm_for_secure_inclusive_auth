# TASKER REPORT — Iteration 9 · Step 25

## SUMMARY
- Raw tasks from Tasker: 6
- Effective task_list after retention: 6
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Make recovery-code generation and validation use the same permitted character set, and verify every displayed recovery code is accepted exactly once before being marked used.","Generate identity codes, provisioning secrets, authenticator test codes, and recovery codes with cryptographically secure random values; retain browser-console mock logging without making values deterministic.","Implement server-side TOTP verification derived from each provisioned secret, with a bounded time window and replay prevention for an accepted time slot.","On every provisioning or replacement request, create a distinct secret and provisioning URI and invalidate all prior pending provisioning secrets, OTP state, and URIs.","Hash each recovery code with a per-code random salt using a slow WebCrypto KDF such as PBKDF2 with an appropriate iteration count before storing it.","Update UI confirmations and browser-console test-value presentation so they accurately reflect secure generation, expiry, replacement invalidation, and one-use verification semantics."]}
```

## PARSED_TASKS
- Make recovery-code generation and validation use the same permitted character set, and verify every displayed recovery code is accepted exactly once before being marked used.
- Generate identity codes, provisioning secrets, authenticator test codes, and recovery codes with cryptographically secure random values; retain browser-console mock logging without making values deterministic.
- Implement server-side TOTP verification derived from each provisioned secret, with a bounded time window and replay prevention for an accepted time slot.
- On every provisioning or replacement request, create a distinct secret and provisioning URI and invalidate all prior pending provisioning secrets, OTP state, and URIs.
- Hash each recovery code with a per-code random salt using a slow WebCrypto KDF such as PBKDF2 with an appropriate iteration count before storing it.
- Update UI confirmations and browser-console test-value presentation so they accurately reflect secure generation, expiry, replacement invalidation, and one-use verification semantics.