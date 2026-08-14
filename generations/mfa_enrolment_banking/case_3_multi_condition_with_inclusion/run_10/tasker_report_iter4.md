# TASKER REPORT — Iteration 4 · Step 10

## SUMMARY
- Raw tasks from Tasker: 6
- Effective task_list after retention: 6
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Update QR provisioning so the generated otpauth URI always renders as a scannable QR code without client errors, while retaining a copyable manual setup key and interoperable TOTP parameters.","Verify the provisioning screen renders the QR code, manual setup key, and OTP verification form, and that the normal MFA enrolment path can complete end-to-end.","Preserve and enforce an active identity-verification lockout in /api/identity/request; do not issue a new code or reset failure state until the lockout expires.","Generate a new CSP nonce for every HTML response and apply that exact nonce to the response CSP header and its inline style and script tags.","Allow users to hide and reveal the current recovery codes while they remain on the backup-code step, and explain plainly that leaving the step requires intentional replacement because prior codes cannot be recovered.","Provide clearly scoped deterministic mock values for simulated identity delivery, authenticator testing, and recovery-code testing, log them only in the browser console as required, and preserve working verification behavior."]}
```

## PARSED_TASKS
- Update QR provisioning so the generated otpauth URI always renders as a scannable QR code without client errors, while retaining a copyable manual setup key and interoperable TOTP parameters.
- Verify the provisioning screen renders the QR code, manual setup key, and OTP verification form, and that the normal MFA enrolment path can complete end-to-end.
- Preserve and enforce an active identity-verification lockout in /api/identity/request; do not issue a new code or reset failure state until the lockout expires.
- Generate a new CSP nonce for every HTML response and apply that exact nonce to the response CSP header and its inline style and script tags.
- Allow users to hide and reveal the current recovery codes while they remain on the backup-code step, and explain plainly that leaving the step requires intentional replacement because prior codes cannot be recovered.
- Provide clearly scoped deterministic mock values for simulated identity delivery, authenticator testing, and recovery-code testing, log them only in the browser console as required, and preserve working verification behavior.