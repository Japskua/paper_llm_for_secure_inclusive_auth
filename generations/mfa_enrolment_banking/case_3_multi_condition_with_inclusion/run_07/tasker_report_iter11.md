# TASKER REPORT — Iteration 11 · Step 31

## SUMMARY
- Raw tasks from Tasker: 6
- Effective task_list after retention: 6
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Add an authenticatorVerified boolean to each MFA state, initialize it false, and reset it false whenever a new authenticator secret is created or replaced.","Set authenticatorVerified true only after a successful standard OTP verification or successful academic mock OTP verification.","Require authenticatorVerified before generating backup codes, returning a clear instruction to verify the authenticator first when it is false.","Require authenticatorVerified before completing MFA enrolment, returning a clear instruction to verify the authenticator first when it is false.","Replace the decorative pseudo-QR with an in-browser standards-compliant QR encoder that encodes the otpauth provisioning URI and renders a scanner-readable QR code without external assets or network calls.","Retain accessible copy controls for both the manual Base32 secret and provisioning URI alongside the valid QR code."]}
```

## PARSED_TASKS
- Add an authenticatorVerified boolean to each MFA state, initialize it false, and reset it false whenever a new authenticator secret is created or replaced.
- Set authenticatorVerified true only after a successful standard OTP verification or successful academic mock OTP verification.
- Require authenticatorVerified before generating backup codes, returning a clear instruction to verify the authenticator first when it is false.
- Require authenticatorVerified before completing MFA enrolment, returning a clear instruction to verify the authenticator first when it is false.
- Replace the decorative pseudo-QR with an in-browser standards-compliant QR encoder that encodes the otpauth provisioning URI and renders a scanner-readable QR code without external assets or network calls.
- Retain accessible copy controls for both the manual Base32 secret and provisioning URI alongside the valid QR code.