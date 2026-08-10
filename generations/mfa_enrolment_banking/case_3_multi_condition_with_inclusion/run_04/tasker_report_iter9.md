# TASKER REPORT — Iteration 9 · Step 25

## SUMMARY
- Raw tasks from Tasker: 5
- Effective task_list after retention: 5
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Replace public identity-proof auto-success with a mock login step that verifies a deterministic test credential server-side before associating a session with the Marcus account; do not disclose the credential in server logs, URLs, or error responses.","Require a valid pre-authenticated session owned by the account before `/api/proof/start` and `/api/proof/complete` can issue or rotate an authenticated owner session; reject all other callers without granting assertions or account identity.","Change `GET /api/session` so unauthenticated callers receive only anonymous bootstrap data and never receive `mfaEnabled` or `recoveryGenerated`; return those fields only after confirming the session belongs to the account owner.","Replace the decorative QR rendering with an inline standards-compliant QR encoder that encodes the exact returned `otpauth://` provisioning URI and produces a scannable matrix.","If a compliant inline QR encoder is not provided, remove the QR-code option and retain the reveal/copy manual-secret provisioning path."]}
```

## PARSED_TASKS
- Replace public identity-proof auto-success with a mock login step that verifies a deterministic test credential server-side before associating a session with the Marcus account; do not disclose the credential in server logs, URLs, or error responses.
- Require a valid pre-authenticated session owned by the account before /api/proof/start and /api/proof/complete can issue or rotate an authenticated owner session; reject all other callers without granting assertions or account identity.
- Change GET /api/session so unauthenticated callers receive only anonymous bootstrap data and never receive mfaEnabled or recoveryGenerated; return those fields only after confirming the session belongs to the account owner.
- Replace the decorative QR rendering with an inline standards-compliant QR encoder that encodes the exact returned otpauth:// provisioning URI and produces a scannable matrix.
- If a compliant inline QR encoder is not provided, remove the QR-code option and retain the reveal/copy manual-secret provisioning path.