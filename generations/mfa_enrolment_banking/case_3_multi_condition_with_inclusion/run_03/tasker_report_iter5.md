# TASKER REPORT — Iteration 5 · Step 13

## SUMMARY
- Raw tasks from Tasker: 6
- Effective task_list after retention: 6
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Replace `renderQr()` with a dependency-free, standards-compliant QR encoder that encodes the `otpauth://` provisioning URI and is scannable by common authenticator apps.","Add a clearly labelled manual authenticator setup key that displays the Base32 secret in a selectable field with a copy action and concise fallback instructions.","Restrict credentialed CORS to an exact configured HTTPS application origin including port; do not emit CORS headers for other localhost or IP origins.","Keep `/api/status` and its CSRF token same-origin only, preventing cross-origin reads even from non-approved local origins.","Gate mock identity codes, provisioning URIs/secrets, TOTP values, recovery-code API fixture fields, and browser console logging behind `MFA_TEST_FIXTURES === \"1\"`; normal operation must not expose them except for the required user-facing recovery-code saving screen.","Replace all `ABCDE-FGHIJ` recovery-code examples, placeholders, and validation guidance with a value accepted by the recovery-code grammar, such as `ABCDE-FGHJK`."]}
```

## PARSED_TASKS
- Replace renderQr() with a dependency-free, standards-compliant QR encoder that encodes the otpauth:// provisioning URI and is scannable by common authenticator apps.
- Add a clearly labelled manual authenticator setup key that displays the Base32 secret in a selectable field with a copy action and concise fallback instructions.
- Restrict credentialed CORS to an exact configured HTTPS application origin including port; do not emit CORS headers for other localhost or IP origins.
- Keep /api/status and its CSRF token same-origin only, preventing cross-origin reads even from non-approved local origins.
- Gate mock identity codes, provisioning URIs/secrets, TOTP values, recovery-code API fixture fields, and browser console logging behind `MFA_TEST_FIXTURES === "1"`; normal operation must not expose them except for the required user-facing recovery-code saving screen.
- Replace all ABCDE-FGHIJ recovery-code examples, placeholders, and validation guidance with a value accepted by the recovery-code grammar, such as ABCDE-FGHJK.