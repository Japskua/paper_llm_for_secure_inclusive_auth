# TASKER REPORT — Iteration 11 · Step 31

## SUMMARY
- Raw tasks from Tasker: 4
- Effective task_list after retention: 4
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Replace the default fixed identity code with a cryptographically random six-digit code; keep a deterministic identity code only in an explicit test-only mode such as `MFA_TEST_MODE=1`.","Add an expiry timestamp for the test-mode authenticator verification value, enforce that expiry in `/api/otp/verify`, and invalidate or reset the test OTP when provisioning is regenerated.","Change deterministic test recovery-code generation so each regeneration round returns a distinct deterministic set, ensuring every previously issued test recovery code fails after replacement.","Add concise comments throughout `app.ts` that explicitly map the relevant UI, authorization/CSRF, headers/TLS, cryptographic storage, validation/XSS, and authentication/rate-limit logic to Requirements 1–5 and the inclusivity requirements."]}
```

## PARSED_TASKS
- Replace the default fixed identity code with a cryptographically random six-digit code; keep a deterministic identity code only in an explicit test-only mode such as `MFA_TEST_MODE=1`.
- Add an expiry timestamp for the test-mode authenticator verification value, enforce that expiry in /api/otp/verify, and invalidate or reset the test OTP when provisioning is regenerated.
- Change deterministic test recovery-code generation so each regeneration round returns a distinct deterministic set, ensuring every previously issued test recovery code fails after replacement.
- Add concise comments throughout app.ts that explicitly map the relevant UI, authorization/CSRF, headers/TLS, cryptographic storage, validation/XSS, and authentication/rate-limit logic to Requirements 1–5 and the inclusivity requirements.