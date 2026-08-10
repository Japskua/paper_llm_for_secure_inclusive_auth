# TASKER REPORT — Iteration 2 · Step 4

## SUMMARY
- Raw tasks from Tasker: 7
- Effective task_list after retention: 7
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Generate a standards-compatible QR code in the browser that encodes the displayed `otpauth://totp/...` provisioning URI, while retaining a copyable manual secret/setup URI option.","Implement server-side TOTP verification using the encrypted provisioned seed, accepting current and adjacent time steps and returning a valid browser-logged test code derived from that seed.","Make identity verification codes, authenticator test codes, and recovery codes deterministic for the test flow while preserving their required validation and single-use behavior.","Persist identity-verification failure counts and lockout state independently of newly issued codes, and rate-limit code issuance so requesting another code cannot bypass a lockout.","Persist authenticator-provisioning failure counts and lockout state independently of a replacement provisioning request, and rate-limit provisioning so it cannot reset failed-attempt protection.","Replace the CSP `script-src 'unsafe-inline'` directive with a per-response nonce or hash that permits only the application’s intended inline script.","If inline styles remain, authorize them with the same nonce/hash approach or move them to nonce-authorized style content so CSP does not require unrestricted `style-src 'unsafe-inline'`."]}
```

## PARSED_TASKS
- Generate a standards-compatible QR code in the browser that encodes the displayed otpauth://totp/... provisioning URI, while retaining a copyable manual secret/setup URI option.
- Implement server-side TOTP verification using the encrypted provisioned seed, accepting current and adjacent time steps and returning a valid browser-logged test code derived from that seed.
- Make identity verification codes, authenticator test codes, and recovery codes deterministic for the test flow while preserving their required validation and single-use behavior.
- Persist identity-verification failure counts and lockout state independently of newly issued codes, and rate-limit code issuance so requesting another code cannot bypass a lockout.
- Persist authenticator-provisioning failure counts and lockout state independently of a replacement provisioning request, and rate-limit provisioning so it cannot reset failed-attempt protection.
- Replace the CSP script-src 'unsafe-inline' directive with a per-response nonce or hash that permits only the application’s intended inline script.
- If inline styles remain, authorize them with the same nonce/hash approach or move them to nonce-authorized style content so CSP does not require unrestricted style-src 'unsafe-inline'.