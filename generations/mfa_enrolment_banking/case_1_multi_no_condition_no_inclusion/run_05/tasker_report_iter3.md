# TASKER REPORT — Iteration 3 · Step 7

## SUMMARY
- Raw tasks from Tasker: 4
- Effective task_list after retention: 4
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Replace email-selected sign-in with a server-validated mock credential flow that establishes only a trusted authenticated principal; reject attempts to select or supply another account identity.","Bind every MFA setup, verification, recovery-code use, and recovery-code regeneration operation exclusively to the authenticated session principal, never to client-supplied user or account identifiers.","Generate a cryptographically secure unique six-digit identity verification code after trusted-principal authentication, hash it server-side, and bind its expiry and single-use state to that session/account.","Return the generated identity test code only for the authenticated demo session so the browser can console.log it, while preserving expiry, single-use, and failed-attempt rate limits."]}
```

## PARSED_TASKS
- Replace email-selected sign-in with a server-validated mock credential flow that establishes only a trusted authenticated principal; reject attempts to select or supply another account identity.
- Bind every MFA setup, verification, recovery-code use, and recovery-code regeneration operation exclusively to the authenticated session principal, never to client-supplied user or account identifiers.
- Generate a cryptographically secure unique six-digit identity verification code after trusted-principal authentication, hash it server-side, and bind its expiry and single-use state to that session/account.
- Return the generated identity test code only for the authenticated demo session so the browser can console.log it, while preserving expiry, single-use, and failed-attempt rate limits.