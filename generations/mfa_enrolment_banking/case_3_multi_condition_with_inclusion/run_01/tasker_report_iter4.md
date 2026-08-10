# TASKER REPORT — Iteration 4 · Step 10

## SUMMARY
- Raw tasks from Tasker: 5
- Effective task_list after retention: 5
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Replace qrSvg() with a real, dynamically generated QR code whose encoded payload is exactly the server-returned otpauth://totp/... provisioning URI. Keep QR generation fully self-contained in app.ts with no external APIs or assets.","Require account.identityVerified === true in /api/authenticator/verify before accepting a TOTP code or enabling MFA.","Enforce current-session authorization for /api/backup/confirm, /api/recovery/regenerate, and /api/recovery/verify by requiring account.identityVerified === true or an equivalent documented recent step-up condition.","When an MFA API response says identity verification is required, route the client to the identity-check screen and show a clear message that the check must be completed before MFA or recovery-code settings can change.","Update authenticator setup instructions to claim QR scanning only when the displayed QR code genuinely encodes the provisioning URI."]}
```

## PARSED_TASKS
- Replace qrSvg() with a real, dynamically generated QR code whose encoded payload is exactly the server-returned otpauth://totp/... provisioning URI. Keep QR generation fully self-contained in app.ts with no external APIs or assets.
- Require account.identityVerified === true in /api/authenticator/verify before accepting a TOTP code or enabling MFA.
- Enforce current-session authorization for /api/backup/confirm, /api/recovery/regenerate, and /api/recovery/verify by requiring account.identityVerified === true or an equivalent documented recent step-up condition.
- When an MFA API response says identity verification is required, route the client to the identity-check screen and show a clear message that the check must be completed before MFA or recovery-code settings can change.
- Update authenticator setup instructions to claim QR scanning only when the displayed QR code genuinely encodes the provisioning URI.