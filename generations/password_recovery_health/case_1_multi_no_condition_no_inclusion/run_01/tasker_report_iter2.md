# TASKER REPORT — Iteration 2 · Step 4

## SUMMARY
- Raw tasks from Tasker: 5
- Effective task_list after retention: 5
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Require TLS certificates at certs/cert.pem and certs/key.pem at startup; if either is unavailable, stop with a generic configuration error and never serve recovery endpoints over HTTP. Run the fixed-origin HTTP-to-HTTPS redirect listener only after the TLS server starts.","Make the reset-request API return the same status, message, and JSON field shape for every submitted identifier, with no conditional delivery data or other account-existence signal.","Replace the hardcoded patient-style email trigger with a non-identifying academic test identifier and require a simulated account-ownership proof before issuing a reset token. After successful proof, return and browser-console-log the deterministic mock delivery token/link required for testing.","Add server-shared throttling for reset requests, reset-token verification failures, and MFA verification failures using a scope that persists across newly created sessions, such as client address plus action and a bounded global fallback.","Add an explicit post-MFA privacy-conditions screen that displays the conditions and requires affirmative checkbox consent. Submit consent to a CSRF-protected endpoint, persist session privacyAccepted state, and allow the final appointment confirmation only after successful consent."]}
```

## PARSED_TASKS
- Require TLS certificates at certs/cert.pem and certs/key.pem at startup; if either is unavailable, stop with a generic configuration error and never serve recovery endpoints over HTTP. Run the fixed-origin HTTP-to-HTTPS redirect listener only after the TLS server starts.
- Make the reset-request API return the same status, message, and JSON field shape for every submitted identifier, with no conditional delivery data or other account-existence signal.
- Replace the hardcoded patient-style email trigger with a non-identifying academic test identifier and require a simulated account-ownership proof before issuing a reset token. After successful proof, return and browser-console-log the deterministic mock delivery token/link required for testing.
- Add server-shared throttling for reset requests, reset-token verification failures, and MFA verification failures using a scope that persists across newly created sessions, such as client address plus action and a bounded global fallback.
- Add an explicit post-MFA privacy-conditions screen that displays the conditions and requires affirmative checkbox consent. Submit consent to a CSRF-protected endpoint, persist session privacyAccepted state, and allow the final appointment confirmation only after successful consent.