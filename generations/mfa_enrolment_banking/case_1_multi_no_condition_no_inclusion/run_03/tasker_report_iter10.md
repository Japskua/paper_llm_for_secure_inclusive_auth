# TASKER REPORT — Iteration 10 · Step 28

## SUMMARY
- Raw tasks from Tasker: 3
- Effective task_list after retention: 3
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Replace fixed-time OTP verification with a real current-time TOTP validation flow:\n  Generate the test fixture using the current TOTP period or a clearly scoped deterministic test clock.\n  Validate against the current 30-second period, optionally allowing only a narrowly bounded adjacent-window skew.\n  Ensure the accepted OTP expires when its TOTP period ends.","Update the browser status() routing logic:\n  If data.recoveryPending is true, render the recovery-code acknowledgement view rather than the dashboard.\n  Preserve or re-fetch the pending recovery codes only through a secure, explicitly authorized, one-time display design, or require a deliberate regeneration flow if codes cannot safely be redisplayed.","Implement a recovery-code verification endpoint:\n  Accept a manually entered recovery code.\n  Validate it against stored PBKDF2 verifiers.\n  Remove the matched verifier after successful use.\n  Apply the existing recovery failure counter and lockout fields.\n  Require the same session authorization, CSRF protection, input validation, and generic error responses as other MFA endpoints."]}
```

## PARSED_TASKS
- Replace fixed-time OTP verification with a real current-time TOTP validation flow:
  Generate the test fixture using the current TOTP period or a clearly scoped deterministic test clock.
  Validate against the current 30-second period, optionally allowing only a narrowly bounded adjacent-window skew.
  Ensure the accepted OTP expires when its TOTP period ends.
- Update the browser status() routing logic:
  If data.recoveryPending is true, render the recovery-code acknowledgement view rather than the dashboard.
  Preserve or re-fetch the pending recovery codes only through a secure, explicitly authorized, one-time display design, or require a deliberate regeneration flow if codes cannot safely be redisplayed.
- Implement a recovery-code verification endpoint:
  Accept a manually entered recovery code.
  Validate it against stored PBKDF2 verifiers.
  Remove the matched verifier after successful use.
  Apply the existing recovery failure counter and lockout fields.
  Require the same session authorization, CSRF protection, input validation, and generic error responses as other MFA endpoints.