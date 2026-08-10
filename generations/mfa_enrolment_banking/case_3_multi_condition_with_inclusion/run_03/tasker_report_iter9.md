# TASKER REPORT — Iteration 9 · Step 25

## SUMMARY
- Raw tasks from Tasker: 5
- Effective task_list after retention: 5
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Replace `drawQr()` with an inline, standards-compliant QR encoder that produces a scannable QR code for the exact `otpauth://` provisioning URI; retain manual-secret display and copy controls.","Enforce recovery workflow guards server-side: require `user.enabled === true` for recovery regeneration, acknowledgement, and verification; require an issued recovery-code set for acknowledgement and verification; return plain-language guidance to finish authenticator verification first.","Store an issuance and expiry timestamp for each recovery-code set. Reject expired recovery codes, require a new set to be generated, and clearly state that the previous codes no longer work.","Preserve authenticator failed-attempt and lockout state when authenticator setup is requested. Reject setup while the authenticator guard is locked, and clear authenticator failures only after successful authenticator verification.","Keep academic mock OTPs, provisioning secrets/URIs, and recovery codes in the browser console only when mock mode is enabled. Ensure the visible `#logs` panel records only non-sensitive status events."]}
```

## PARSED_TASKS
- Replace drawQr() with an inline, standards-compliant QR encoder that produces a scannable QR code for the exact otpauth:// provisioning URI; retain manual-secret display and copy controls.
- Enforce recovery workflow guards server-side: require user.enabled === true for recovery regeneration, acknowledgement, and verification; require an issued recovery-code set for acknowledgement and verification; return plain-language guidance to finish authenticator verification first.
- Store an issuance and expiry timestamp for each recovery-code set. Reject expired recovery codes, require a new set to be generated, and clearly state that the previous codes no longer work.
- Preserve authenticator failed-attempt and lockout state when authenticator setup is requested. Reject setup while the authenticator guard is locked, and clear authenticator failures only after successful authenticator verification.
- Keep academic mock OTPs, provisioning secrets/URIs, and recovery codes in the browser console only when mock mode is enabled. Ensure the visible #logs panel records only non-sensitive status events.