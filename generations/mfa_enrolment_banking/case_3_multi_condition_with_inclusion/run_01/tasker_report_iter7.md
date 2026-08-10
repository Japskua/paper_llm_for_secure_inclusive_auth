# TASKER REPORT — Iteration 7 · Step 19

## SUMMARY
- Raw tasks from Tasker: 6
- Effective task_list after retention: 6
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Add an authenticated, CSRF-protected server endpoint for recovery-code verification that accepts only valid recovery-code input and derives the account solely from the current session.","Verify submitted recovery codes against stored HMAC verifiers with constant-time comparison, and remove the matched verifier after a successful verification so each code is single-use.","Implement recovery-code failed-attempt counting, five-attempt lockout, and expiry reset logic; after `recoveryLockedUntil` has passed, reset both the lock timestamp and failed-attempt count before evaluating a new attempt.","Before evaluating each OTP attempt, reset `otpFailedAttempts` and `otpLockedUntil` when an existing OTP lock has expired, so a user can retry normally after the lock period.","Add a mobile-accessible authenticated recovery-code verification screen or flow with a recovery-code input, plain-language success/error feedback, and a retry path.","Remove the visible in-page logs panel or ensure it never renders OTPs, authenticator secrets, recovery codes, session values, or other sensitive mock data; retain required mock disclosures only in browser `console.log` output."]}
```

## PARSED_TASKS
- Add an authenticated, CSRF-protected server endpoint for recovery-code verification that accepts only valid recovery-code input and derives the account solely from the current session.
- Verify submitted recovery codes against stored HMAC verifiers with constant-time comparison, and remove the matched verifier after a successful verification so each code is single-use.
- Implement recovery-code failed-attempt counting, five-attempt lockout, and expiry reset logic; after recoveryLockedUntil has passed, reset both the lock timestamp and failed-attempt count before evaluating a new attempt.
- Before evaluating each OTP attempt, reset otpFailedAttempts and otpLockedUntil when an existing OTP lock has expired, so a user can retry normally after the lock period.
- Add a mobile-accessible authenticated recovery-code verification screen or flow with a recovery-code input, plain-language success/error feedback, and a retry path.
- Remove the visible in-page logs panel or ensure it never renders OTPs, authenticator secrets, recovery codes, session values, or other sensitive mock data; retain required mock disclosures only in browser console.log output.