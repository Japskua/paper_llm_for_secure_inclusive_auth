# TASKER REPORT — Iteration 9 · Step 25

## SUMMARY
- Raw tasks from Tasker: 11
- Effective task_list after retention: 11
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Add clipboard controls for the authenticator setup secret and recovery-code list, with clear success or error feedback and no external dependencies.","Add accessible hide/reveal controls for the authenticator secret and recovery codes, with sensitive recovery values initially protected from casual viewing.","Add `autocomplete=\"username\"` and an appropriate `inputmode` to the email field, and add `autocomplete=\"current-password\"` to the password field.","Add `autocomplete=\"one-time-code\"`, `inputmode=\"numeric\"`, `maxlength=\"6\"`, and numeric pattern validation to every six-digit OTP input.","Implement failed-attempt counting and a 15-minute lockout for `/api/identity/verify`, resetting failures after success and returning a clear, non-blaming lockout message.","Implement failed-attempt counting and lockout for `/api/signin`, reset the counter after successful authentication, and keep authentication failure responses generic.","Replace non-academic identity-code generation using `Math.random()` with a cryptographically secure six-digit generator based on `crypto.getRandomValues`.","Gate all browser-console output containing identity, TOTP, or recovery codes behind academic mode, including logging recovery codes only when academic mode is enabled.","Update each client action to verify its API response before advancing screens, keeping the current screen visible and showing returned errors when a request fails.","Render the MFA completion screen only after `/api/recovery/finish` returns `{ ok: true }`.","Extend `/api/me` bootstrap routing to restore authenticated sessions at the `identity`, `setup`, `confirm`, `recovery`, and `complete` stages."]}
```

## PARSED_TASKS
- Add clipboard controls for the authenticator setup secret and recovery-code list, with clear success or error feedback and no external dependencies.
- Add accessible hide/reveal controls for the authenticator secret and recovery codes, with sensitive recovery values initially protected from casual viewing.
- Add autocomplete="username" and an appropriate inputmode to the email field, and add autocomplete="current-password" to the password field.
- Add autocomplete="one-time-code", inputmode="numeric", maxlength="6", and numeric pattern validation to every six-digit OTP input.
- Implement failed-attempt counting and a 15-minute lockout for /api/identity/verify, resetting failures after success and returning a clear, non-blaming lockout message.
- Implement failed-attempt counting and lockout for /api/signin, reset the counter after successful authentication, and keep authentication failure responses generic.
- Replace non-academic identity-code generation using Math.random() with a cryptographically secure six-digit generator based on crypto.getRandomValues.
- Gate all browser-console output containing identity, TOTP, or recovery codes behind academic mode, including logging recovery codes only when academic mode is enabled.
- Update each client action to verify its API response before advancing screens, keeping the current screen visible and showing returned errors when a request fails.
- Render the MFA completion screen only after /api/recovery/finish returns { ok: true }.
- Extend /api/me bootstrap routing to restore authenticated sessions at the identity, setup, confirm, recovery, and complete stages.