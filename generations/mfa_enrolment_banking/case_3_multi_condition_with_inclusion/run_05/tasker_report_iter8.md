# TASKER REPORT — Iteration 8 · Step 22

## SUMMARY
- Raw tasks from Tasker: 5
- Effective task_list after retention: 5
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Replace qrCanvas() with a self-contained, standards-compliant QR Code encoder that encodes the generated otpauth:// URI into a scannable canvas image without external libraries or network dependencies.","Change the identity verification UI so exactly one action is visually primary at a time; make code sending secondary or only show confirmation after a code request.","Add an authenticated, CSRF-protected recovery-code verification endpoint and UI that accepts one code, verifies it against stored codes, consumes it on success, rejects reuse, rate-limits failures, and gives clear non-enumerating messages.","Store each recovery code with PBKDF2 or another slow KDF using a unique cryptographically random salt and high iteration count, and update recovery-code verification to use that stored format.","Count invalid manual authenticator setup-secret submissions toward the existing authenticator failure limit and enforce the configured ten-minute lockout after the maximum failures."]}
```

## PARSED_TASKS
- Replace qrCanvas() with a self-contained, standards-compliant QR Code encoder that encodes the generated otpauth:// URI into a scannable canvas image without external libraries or network dependencies.
- Change the identity verification UI so exactly one action is visually primary at a time; make code sending secondary or only show confirmation after a code request.
- Add an authenticated, CSRF-protected recovery-code verification endpoint and UI that accepts one code, verifies it against stored codes, consumes it on success, rejects reuse, rate-limits failures, and gives clear non-enumerating messages.
- Store each recovery code with PBKDF2 or another slow KDF using a unique cryptographically random salt and high iteration count, and update recovery-code verification to use that stored format.
- Count invalid manual authenticator setup-secret submissions toward the existing authenticator failure limit and enforce the configured ten-minute lockout after the maximum failures.