# TASKER REPORT — Iteration 3 · Step 7

## SUMMARY
- Raw tasks from Tasker: 5
- Effective task_list after retention: 5
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Generate a cryptographically random six-digit identity verification code for each request, bind it to the authenticated session and expiry, mark it single-use after successful verification, and return it only for browser-console mock delivery (never server logs, URLs, or errors).","Preserve failed-attempt counts and lockout-until timestamps for identity verification across code re-requests; reject new-code requests and verification attempts while the identity flow is locked.","Preserve failed-attempt counts and lockout-until timestamps for authenticator activation across provisioning restarts; reject new provisioning requests and activation attempts while the authenticator flow is locked.","Implement server-side RFC-compatible TOTP validation using the encrypted provisioned secret and the current 30-second counter, accepting only a small defined clock-skew window and preventing reuse of a successfully accepted time-step.","For test visibility, provide the current valid authenticator mock OTP to the browser solely for console.log output without using a globally fixed OTP; retain per-secret validation, expiry by TOTP window, and lockout protections."]}
```

## PARSED_TASKS
- Generate a cryptographically random six-digit identity verification code for each request, bind it to the authenticated session and expiry, mark it single-use after successful verification, and return it only for browser-console mock delivery (never server logs, URLs, or errors).
- Preserve failed-attempt counts and lockout-until timestamps for identity verification across code re-requests; reject new-code requests and verification attempts while the identity flow is locked.
- Preserve failed-attempt counts and lockout-until timestamps for authenticator activation across provisioning restarts; reject new provisioning requests and activation attempts while the authenticator flow is locked.
- Implement server-side RFC-compatible TOTP validation using the encrypted provisioned secret and the current 30-second counter, accepting only a small defined clock-skew window and preventing reuse of a successfully accepted time-step.
- For test visibility, provide the current valid authenticator mock OTP to the browser solely for console.log output without using a globally fixed OTP; retain per-secret validation, expiry by TOTP window, and lockout protections.