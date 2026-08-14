# TASKER REPORT — Iteration 2 · Step 4

## SUMMARY
- Raw tasks from Tasker: 4
- Effective task_list after retention: 4
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Replace the static MFA confirmation code with RFC 6238-compatible TOTP derived from the generated base32 setup secret, using a 30-second step and a narrowly defined clock-skew window.","Update `/api/mfa/confirm` to decrypt the draft seed only within the confirmation path and validate the submitted six-digit code against the derived TOTP instead of any stored OTP value.","Remove plaintext `manualSecret` and `otp` fields from the server-side `Draft` state; retain only AES-GCM-encrypted seed material and required expiry, attempt, and lockout metadata.","Add an `identityCodeExpiresAt` timestamp when issuing an identity code, and reject and clear the code after a short independent validity window regardless of session lifetime."]}
```

## PARSED_TASKS
- Replace the static MFA confirmation code with RFC 6238-compatible TOTP derived from the generated base32 setup secret, using a 30-second step and a narrowly defined clock-skew window.
- Update /api/mfa/confirm to decrypt the draft seed only within the confirmation path and validate the submitted six-digit code against the derived TOTP instead of any stored OTP value.
- Remove plaintext manualSecret and otp fields from the server-side Draft state; retain only AES-GCM-encrypted seed material and required expiry, attempt, and lockout metadata.
- Add an identityCodeExpiresAt timestamp when issuing an identity code, and reject and clear the code after a short independent validity window regardless of session lifetime.