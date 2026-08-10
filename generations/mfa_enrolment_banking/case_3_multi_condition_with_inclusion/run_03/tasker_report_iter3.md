# TASKER REPORT — Iteration 3 · Step 7

## SUMMARY
- Raw tasks from Tasker: 4
- Effective task_list after retention: 4
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Replace the fixed QR encoder with an in-file encoder that selects a version and error-correction capacity sufficient for the complete generated `otpauth://` provisioning URI. Check capacity before rendering so an oversized or invalid QR code is never offered.","Make `/api/mfa/verify` accept only a code derived from the authenticated user's decrypted provisioned secret, with an allowed clock window and single-use protection for an accepted time step. Ensure the provisioning URI/manual setup key and the browser-console mock code correspond to the exact verification method.","Replace random simulated OTP delivery values with deterministic mock values that the relevant verification endpoint accepts, while preserving expiry, single-use behavior, retry limits, and lockout handling.","Remove `unsafe-inline` from CSP `script-src` and `style-src`; generate a fresh per-response nonce, apply it to the inline style and script elements, and include that nonce in the CSP header."]}
```

## PARSED_TASKS
- Replace the fixed QR encoder with an in-file encoder that selects a version and error-correction capacity sufficient for the complete generated otpauth:// provisioning URI. Check capacity before rendering so an oversized or invalid QR code is never offered.
- Make /api/mfa/verify accept only a code derived from the authenticated user's decrypted provisioned secret, with an allowed clock window and single-use protection for an accepted time step. Ensure the provisioning URI/manual setup key and the browser-console mock code correspond to the exact verification method.
- Replace random simulated OTP delivery values with deterministic mock values that the relevant verification endpoint accepts, while preserving expiry, single-use behavior, retry limits, and lockout handling.
- Remove unsafe-inline from CSP script-src and style-src; generate a fresh per-response nonce, apply it to the inline style and script elements, and include that nonce in the CSP header.