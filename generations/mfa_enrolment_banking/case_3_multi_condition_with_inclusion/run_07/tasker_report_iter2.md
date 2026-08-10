# TASKER REPORT — Iteration 2 · Step 4

## SUMMARY
- Raw tasks from Tasker: 9
- Effective task_list after retention: 9
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Refactor client rendering so setup does not reference an out-of-scope variable, and verify the browser flow from sign-in through completion has no client runtime errors.","Restrict server-side mock authentication to the configured account email after normalization; return the same generic sign-in failure for invalid or non-matching emails.","Implement setup-key creation by calling POST /api/setup, retaining returned provisioning data only in client memory and allowing the user to recreate setup data.","Replace the decorative QR-style grid with a locally generated, scannable QR code that encodes the returned otpauth URI, while retaining copyable manual-secret entry.","After OTP verification, provide a backup-code generation action that calls POST /api/backups, keeps returned codes only in memory, and displays them before completion is available.","Add a recovery-code verification screen that submits an entered code to POST /api/recovery/verify, provides specific retry guidance after failure, and confirms successful verification.","Log generated mock recovery codes to the browser console when received, and remove any browser-console logging of the authenticator provisioning secret.","Preserve success notices when navigating to the next screen so each completed action confirms what happened and what to do next.","Make the backup screen stage-specific: show Generate backup codes as the sole primary action before generation, then offer copy, print, and completion actions only after codes exist."]}
```

## PARSED_TASKS
- Refactor client rendering so setup does not reference an out-of-scope variable, and verify the browser flow from sign-in through completion has no client runtime errors.
- Restrict server-side mock authentication to the configured account email after normalization; return the same generic sign-in failure for invalid or non-matching emails.
- Implement setup-key creation by calling POST /api/setup, retaining returned provisioning data only in client memory and allowing the user to recreate setup data.
- Replace the decorative QR-style grid with a locally generated, scannable QR code that encodes the returned otpauth URI, while retaining copyable manual-secret entry.
- After OTP verification, provide a backup-code generation action that calls POST /api/backups, keeps returned codes only in memory, and displays them before completion is available.
- Add a recovery-code verification screen that submits an entered code to POST /api/recovery/verify, provides specific retry guidance after failure, and confirms successful verification.
- Log generated mock recovery codes to the browser console when received, and remove any browser-console logging of the authenticator provisioning secret.
- Preserve success notices when navigating to the next screen so each completed action confirms what happened and what to do next.
- Make the backup screen stage-specific: show Generate backup codes as the sole primary action before generation, then offer copy, print, and completion actions only after codes exist.