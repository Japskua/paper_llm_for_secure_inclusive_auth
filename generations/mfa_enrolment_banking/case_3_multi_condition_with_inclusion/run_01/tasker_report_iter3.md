# TASKER REPORT — Iteration 3 · Step 7

## SUMMARY
- Raw tasks from Tasker: 5
- Effective task_list after retention: 5
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Validate authenticator OTPs with RFC 6238 TOTP derived from the encrypted provisioned secret, using HMAC-SHA-1 and a short clock-skew window; preserve single-use and failed-attempt lockout behavior.","Return and browser-console-log a deterministic test TOTP derived from the same provisioned secret so the displayed QR/manual secret, test code, and server verification all interoperate.","Replace the custom QR generator with an embedded standards-compliant QR encoder that reserves functional modules correctly and produces a scannable code for the exact returned otpauth provisioning URI.","Store recovery-code verifiers using HMAC-SHA-256 with a server-only key or an equivalently strong salted KDF, and compare submitted recovery codes in constant time.","Make sign-in timing independent of account existence by always hashing and comparing the submitted password against either the account hash or a fixed dummy hash before returning the same generic failure response."]}
```

## PARSED_TASKS
- Validate authenticator OTPs with RFC 6238 TOTP derived from the encrypted provisioned secret, using HMAC-SHA-1 and a short clock-skew window; preserve single-use and failed-attempt lockout behavior.
- Return and browser-console-log a deterministic test TOTP derived from the same provisioned secret so the displayed QR/manual secret, test code, and server verification all interoperate.
- Replace the custom QR generator with an embedded standards-compliant QR encoder that reserves functional modules correctly and produces a scannable code for the exact returned otpauth provisioning URI.
- Store recovery-code verifiers using HMAC-SHA-256 with a server-only key or an equivalently strong salted KDF, and compare submitted recovery codes in constant time.
- Make sign-in timing independent of account existence by always hashing and comparing the submitted password against either the account hash or a fixed dummy hash before returning the same generic failure response.