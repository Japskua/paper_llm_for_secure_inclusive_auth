# TASKER REPORT — Iteration 8 · Step 22

## SUMMARY
- Raw tasks from Tasker: 4
- Effective task_list after retention: 4
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Replace `qrVisual()` with an embedded, standards-compliant QR encoder that encodes the exact `provisioningUri` value, without external network assets or dependencies.","Correct `totp()` so the HMAC input is the raw eight-byte counter (`Uint8Array(8)`), not a Base64URL-encoded string representation of that counter.","Update OTP verification so a real RFC 6238 TOTP generated from the shown secret is accepted, including in `TEST_MODE`; retain the deterministic mock OTP as an additional accepted test value and browser-console test aid.","Update the authenticator setup wording only after the QR and TOTP behavior are corrected, so “scan this code” and “enter its six-digit code” accurately describe working behavior."]}
```

## PARSED_TASKS
- Replace qrVisual() with an embedded, standards-compliant QR encoder that encodes the exact provisioningUri value, without external network assets or dependencies.
- Correct totp() so the HMAC input is the raw eight-byte counter (Uint8Array(8)), not a Base64URL-encoded string representation of that counter.
- Update OTP verification so a real RFC 6238 TOTP generated from the shown secret is accepted, including in `TEST_MODE`; retain the deterministic mock OTP as an additional accepted test value and browser-console test aid.
- Update the authenticator setup wording only after the QR and TOTP behavior are corrected, so “scan this code” and “enter its six-digit code” accurately describe working behavior.