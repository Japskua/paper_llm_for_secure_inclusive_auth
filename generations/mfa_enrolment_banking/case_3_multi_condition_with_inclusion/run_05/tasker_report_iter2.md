# TASKER REPORT — Iteration 2 · Step 4

## SUMMARY
- Raw tasks from Tasker: 6
- Effective task_list after retention: 6
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Replace the decorative QR grid with a real, locally generated QR code that encodes an `otpauth://totp/...` provisioning URI containing the generated base32 secret, issuer, account label, algorithm, digits, and period. Keep the manual secret and copy option.","Implement authenticator verification using a TOTP algorithm derived from the provisioned server-side secret, accepting a bounded current-time window and consuming the verified time-step to prevent reuse. In simulation mode, expose only the current valid test code through browser `console.log`.","Use deterministic simulation values for identity verification, provisioning secret/TOTP test behavior, and recovery codes while continuing to reveal those values only in browser console logs.","Fix secret masking so hiding the setup secret does not alter the actual secret submitted to `/api/provision/manual`; submitting while hidden must succeed with the provisioned secret.","Remove plaintext recovery codes from all server session state after generation. Return them only in the immediate successful OTP-verification response while retaining only securely hashed recovery codes server-side.","Add per-session failed-attempt tracking and a timed lockout or rate limit to `/api/recovery/confirm`. Return a clear, non-sensitive message stating that too many incorrect attempts were made and when retry is allowed."]}
```

## PARSED_TASKS
- Replace the decorative QR grid with a real, locally generated QR code that encodes an otpauth://totp/... provisioning URI containing the generated base32 secret, issuer, account label, algorithm, digits, and period. Keep the manual secret and copy option.
- Implement authenticator verification using a TOTP algorithm derived from the provisioned server-side secret, accepting a bounded current-time window and consuming the verified time-step to prevent reuse. In simulation mode, expose only the current valid test code through browser console.log.
- Use deterministic simulation values for identity verification, provisioning secret/TOTP test behavior, and recovery codes while continuing to reveal those values only in browser console logs.
- Fix secret masking so hiding the setup secret does not alter the actual secret submitted to /api/provision/manual; submitting while hidden must succeed with the provisioned secret.
- Remove plaintext recovery codes from all server session state after generation. Return them only in the immediate successful OTP-verification response while retaining only securely hashed recovery codes server-side.
- Add per-session failed-attempt tracking and a timed lockout or rate limit to /api/recovery/confirm. Return a clear, non-sensitive message stating that too many incorrect attempts were made and when retry is allowed.