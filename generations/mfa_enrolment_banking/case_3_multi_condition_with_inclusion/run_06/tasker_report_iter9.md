# TASKER REPORT — Iteration 9 · Step 25

## SUMMARY
- Raw tasks from Tasker: 7
- Effective task_list after retention: 7
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Disable `/api/demo/login` by default and require a validated upstream signed identity assertion or a clearly isolated, explicitly enabled test-only authentication mode before creating an authenticated MFA session.","Make simulated identity delivery functional in enabled demo/test mode by returning a deterministic test code to the browser and logging that exact code with browser `console.log`.","Return and log every simulated testing value in the browser, including identity OTPs, authenticator OTPs, and generated recovery codes, while keeping server/production logs free of secrets.","Replace `qr(uri)` with a standards-compliant, scannable QR encoder for the exact `otpauth://` provisioning URI, while retaining the manual copyable setup-key option.","Replace the global MFA record with MFA records keyed by authenticated `accountId`, and ensure every MFA read/write uses only the owner session’s account record.","When `/api/provision` starts a new enrolment, clear that account’s existing recovery-code hashes and all stale completion/enrolment state.","Require `/api/complete` to verify both a successfully verified authenticator for the current enrolment and recovery codes newly generated for that same enrolment before enabling MFA."]}
```

## PARSED_TASKS
- Disable /api/demo/login by default and require a validated upstream signed identity assertion or a clearly isolated, explicitly enabled test-only authentication mode before creating an authenticated MFA session.
- Make simulated identity delivery functional in enabled demo/test mode by returning a deterministic test code to the browser and logging that exact code with browser console.log.
- Return and log every simulated testing value in the browser, including identity OTPs, authenticator OTPs, and generated recovery codes, while keeping server/production logs free of secrets.
- Replace qr(uri) with a standards-compliant, scannable QR encoder for the exact otpauth:// provisioning URI, while retaining the manual copyable setup-key option.
- Replace the global MFA record with MFA records keyed by authenticated accountId, and ensure every MFA read/write uses only the owner session’s account record.
- When /api/provision starts a new enrolment, clear that account’s existing recovery-code hashes and all stale completion/enrolment state.
- Require /api/complete to verify both a successfully verified authenticator for the current enrolment and recovery codes newly generated for that same enrolment before enabling MFA.