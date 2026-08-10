# TASKER REPORT — Iteration 5 · Step 13

## SUMMARY
- Raw tasks from Tasker: 5
- Effective task_list after retention: 5
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Replace the decorative QR renderer with a self-contained standards-compliant QR encoder whose canvas output encodes the exact `provisioningUri` returned by `/api/mfa/provision` and can be scanned by common authenticator apps.","Remove all browser-console logging of MFA setup secrets and provisioning URIs; retain browser-console mock output only for test OTPs and recovery codes as required.","Remove the visible Logs card and ensure OTPs, recovery codes, setup secrets, provisioning URIs, and other sensitive values are never inserted into the page DOM.","Store each recovery code using a cryptographically random per-code salt and a slow password-hashing/KDF representation rather than unsalted SHA-256.","Update recovery-code verification to derive and compare values using the stored salted slow-KDF representation, while preserving single-use recovery-code behavior."]}
```

## PARSED_TASKS
- Replace the decorative QR renderer with a self-contained standards-compliant QR encoder whose canvas output encodes the exact provisioningUri returned by /api/mfa/provision and can be scanned by common authenticator apps.
- Remove all browser-console logging of MFA setup secrets and provisioning URIs; retain browser-console mock output only for test OTPs and recovery codes as required.
- Remove the visible Logs card and ensure OTPs, recovery codes, setup secrets, provisioning URIs, and other sensitive values are never inserted into the page DOM.
- Store each recovery code using a cryptographically random per-code salt and a slow password-hashing/KDF representation rather than unsalted SHA-256.
- Update recovery-code verification to derive and compare values using the stored salted slow-KDF representation, while preserving single-use recovery-code behavior.