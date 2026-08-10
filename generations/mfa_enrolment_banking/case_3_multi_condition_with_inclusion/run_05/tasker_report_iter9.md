# TASKER REPORT — Iteration 9 · Step 25

## SUMMARY
- Raw tasks from Tasker: 4
- Effective task_list after retention: 4
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Replace the pseudo-random QR display with an in-file standards-compliant QR encoder that encodes the generated `otpauth://` URI and produces a code scannable by authenticator applications.","Make every offered test provisioning secret match the server’s accepted Base32 validation format, or safely broaden validation to accept the generated lengths; verify the initially supplied secret succeeds at `/api/provision/manual`.","Add an authenticated, CSRF-protected recovery-code use endpoint that compares stored hashes safely and atomically marks or removes a matching code so subsequent reuse fails; retain `/api/recovery/confirm` as a non-consuming save-check.","Refactor sign-in validation so malformed, unknown, and known-account attempts perform equivalent credential-comparison work while preserving generic failures and existing rate-limit behavior."]}
```

## PARSED_TASKS
- Replace the pseudo-random QR display with an in-file standards-compliant QR encoder that encodes the generated otpauth:// URI and produces a code scannable by authenticator applications.
- Make every offered test provisioning secret match the server’s accepted Base32 validation format, or safely broaden validation to accept the generated lengths; verify the initially supplied secret succeeds at /api/provision/manual.
- Add an authenticated, CSRF-protected recovery-code use endpoint that compares stored hashes safely and atomically marks or removes a matching code so subsequent reuse fails; retain /api/recovery/confirm as a non-consuming save-check.
- Refactor sign-in validation so malformed, unknown, and known-account attempts perform equivalent credential-comparison work while preserving generic failures and existing rate-limit behavior.