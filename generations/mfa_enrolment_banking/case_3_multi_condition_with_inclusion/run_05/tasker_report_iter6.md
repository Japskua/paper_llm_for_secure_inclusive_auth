# TASKER REPORT — Iteration 6 · Step 16

## SUMMARY
- Raw tasks from Tasker: 4
- Effective task_list after retention: 4
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Replace drawQR() with a standards-compliant, scannable QR-code encoder that encodes the returned otpauth:// provisioning URI; alternatively, remove the scan-QR claim and QR UI entirely while retaining manual secret setup and copy support.","Preserve identity-verification failure and lockout state across /api/identity/resend; add a resend rate limit so requesting a new code cannot bypass the lockout.","Preserve authenticator OTP failure and lockout state across provisioning-secret regeneration, or prohibit /api/provision regeneration while an OTP lockout is active; ensure a new secret cannot reset the OTP verification attempt budget.","Add server-side sign-in throttling/lockout for repeated failed credentials, with generic responses and consistent behavior that does not permit account enumeration."]}
```

## PARSED_TASKS
- Replace drawQR() with a standards-compliant, scannable QR-code encoder that encodes the returned otpauth:// provisioning URI; alternatively, remove the scan-QR claim and QR UI entirely while retaining manual secret setup and copy support.
- Preserve identity-verification failure and lockout state across /api/identity/resend; add a resend rate limit so requesting a new code cannot bypass the lockout.
- Preserve authenticator OTP failure and lockout state across provisioning-secret regeneration, or prohibit /api/provision regeneration while an OTP lockout is active; ensure a new secret cannot reset the OTP verification attempt budget.
- Add server-side sign-in throttling/lockout for repeated failed credentials, with generic responses and consistent behavior that does not permit account enumeration.