# TASKER REPORT — Iteration 9 · Step 25

## SUMMARY
- Raw tasks from Tasker: 7
- Effective task_list after retention: 7
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Replace or correct the in-file QR encoder so provisioning URIs render as standards-compliant, scannable QR codes; verify format-information placement, masking, error correction, and output against known valid test vectors.","Generate a fresh cryptographically random Base32 TOTP secret for each authenticator enrolment and encrypt that per-enrolment secret at rest.","Generate each identity verification OTP with cryptographically secure randomness, store only its hash and challenge metadata server-side, and expose the mock value only to the authenticated browser UI for testing.","Generate each recovery-code set with cryptographically secure randomness, store only code hashes server-side, and expose generated mock codes only to the authenticated browser UI for testing.","Make recovery-code regeneration generate a distinct new random set before replacing existing hashes, so every previously issued recovery code fails after regeneration.","Store verification failure counters and lockout timestamps in account- or challenge-scoped server-side state so logout or a new sign-in session cannot reset a lockout.","Replace hostname-based Origin validation with an explicit allow-list of complete configured HTTPS origins, including the application port, and reject every other origin."]}
```

## PARSED_TASKS
- Replace or correct the in-file QR encoder so provisioning URIs render as standards-compliant, scannable QR codes; verify format-information placement, masking, error correction, and output against known valid test vectors.
- Generate a fresh cryptographically random Base32 TOTP secret for each authenticator enrolment and encrypt that per-enrolment secret at rest.
- Generate each identity verification OTP with cryptographically secure randomness, store only its hash and challenge metadata server-side, and expose the mock value only to the authenticated browser UI for testing.
- Generate each recovery-code set with cryptographically secure randomness, store only code hashes server-side, and expose generated mock codes only to the authenticated browser UI for testing.
- Make recovery-code regeneration generate a distinct new random set before replacing existing hashes, so every previously issued recovery code fails after regeneration.
- Store verification failure counters and lockout timestamps in account- or challenge-scoped server-side state so logout or a new sign-in session cannot reset a lockout.
- Replace hostname-based Origin validation with an explicit allow-list of complete configured HTTPS origins, including the application port, and reject every other origin.