# TASKER REPORT — Iteration 2 · Step 4

## SUMMARY
- Raw tasks from Tasker: 5
- Effective task_list after retention: 5
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Implement a server-side mock authentication model that binds each session to a specific authenticated account. Validate a mock credential or established identity server-side, never use one shared account or overwrite account ownership/email from submitted input, and return generic sign-in failures.","Replace the decorative setup canvas with an inline, valid QR code encoding the provisioned `otpauth://totp/...` URI. Keep the provisioning secret visibly available and copyable as the accessible manual alternative.","Generate each mock OTP using cryptographically secure randomness instead of a fixed value. Return it only through the intended test UI/browser console path, keep it time-bound and single-use, and isolate any deterministic test mode from the default path.","Generate recovery codes using cryptographically secure uppercase letters and digits in the exact accepted `ABCDE-12345` format. Verify that every displayed generated code passes the recovery verification endpoint.","Add failed-attempt tracking, rate limiting, and temporary lockout for recovery-code verification. Give clear non-sensitive retry guidance and reset recovery failure state after successful verification and appropriate new authentication."]}
```

## PARSED_TASKS
- Implement a server-side mock authentication model that binds each session to a specific authenticated account. Validate a mock credential or established identity server-side, never use one shared account or overwrite account ownership/email from submitted input, and return generic sign-in failures.
- Replace the decorative setup canvas with an inline, valid QR code encoding the provisioned otpauth://totp/... URI. Keep the provisioning secret visibly available and copyable as the accessible manual alternative.
- Generate each mock OTP using cryptographically secure randomness instead of a fixed value. Return it only through the intended test UI/browser console path, keep it time-bound and single-use, and isolate any deterministic test mode from the default path.
- Generate recovery codes using cryptographically secure uppercase letters and digits in the exact accepted ABCDE-12345 format. Verify that every displayed generated code passes the recovery verification endpoint.
- Add failed-attempt tracking, rate limiting, and temporary lockout for recovery-code verification. Give clear non-sensitive retry guidance and reset recovery failure state after successful verification and appropriate new authentication.