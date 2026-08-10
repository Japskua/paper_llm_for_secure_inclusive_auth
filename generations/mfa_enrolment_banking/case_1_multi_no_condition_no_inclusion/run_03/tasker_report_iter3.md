# TASKER REPORT — Iteration 3 · Step 7

## SUMMARY
- Raw tasks from Tasker: 4
- Effective task_list after retention: 4
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Add a pending-provisioning expiration timestamp to the server-side MFA record, set it when `/api/mfa/provision` creates a secret, and enforce a bounded validity period before confirmation.","Validate authenticator OTPs against the current 30-second TOTP time step in normal mode, allowing only narrowly defined adjacent-step skew if implemented.","In deterministic test mode, retain a browser-console fixture if needed but reject it once the pending provisioning expiration has passed.","When authenticator provisioning has expired, clear the pending secret/record and return a response requiring the user to generate a fresh provisioning secret before retrying confirmation."]}
```

## PARSED_TASKS
- Add a pending-provisioning expiration timestamp to the server-side MFA record, set it when /api/mfa/provision creates a secret, and enforce a bounded validity period before confirmation.
- Validate authenticator OTPs against the current 30-second TOTP time step in normal mode, allowing only narrowly defined adjacent-step skew if implemented.
- In deterministic test mode, retain a browser-console fixture if needed but reject it once the pending provisioning expiration has passed.
- When authenticator provisioning has expired, clear the pending secret/record and return a response requiring the user to generate a fresh provisioning secret before retrying confirmation.