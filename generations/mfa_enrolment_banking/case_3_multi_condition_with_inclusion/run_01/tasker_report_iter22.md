# TASKER REPORT — Iteration 22 · Step 64

## SUMMARY
- Raw tasks from Tasker: 14
- Effective task_list after retention: 14
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Validate OTPs server-side against the session’s issued challenge value; reject every non-matching six-digit value with a clear fix message.","Record OTP challenge issuance time, expiry, used status, and failed-attempt count in the authenticated server session; expire or consume challenges so they cannot be reused.","Rate-limit failed sign-in and OTP verification attempts server-side, applying a temporary lockout/cooldown and returning the remaining retry time in plain language.","Generate a unique authenticator seed and recovery-code set for each enrolment with a cryptographically secure RNG; remove all hard-coded reusable secrets and codes.","Encrypt each authenticator seed before retaining it server-side and retain only cryptographic hashes of recovery codes; return each plaintext recovery-code set only at generation time.","Enforce server-side session idle and absolute expiry using created and last-seen timestamps, deleting expired sessions before authorizing requests.","Implement a pre-authentication CSRF token flow and require its validation on sign-in; continue requiring session-bound CSRF validation for every authenticated state-changing request.","Strictly validate JSON body shapes and server-side email, password, and OTP types, lengths, and formats before authentication or MFA processing.","Provide recovery-code saving controls for copy-all and download or print, with clipboard fallback and a plain confirmation after the user saves them.","Add a clearly labeled demo/testing mode that logs mock OTP and returned recovery codes with browser console.log only when enabled; keep secret logging absent in normal operation.","Provide secondary setup controls to reveal or hide the authenticator secret, copy the secret and provisioning URI, restart provisioning, and return from verification to setup without penalty.","Add a short contextual help or hint at every flow step and remove the persistent on-page diagnostic log from the standard user interface.","Add an authenticated session-status/settings endpoint and initialize the client from it so a refreshed page restores the signed-in user’s correct MFA enrolment step.","Make each setup and recovery screen have one visually dominant primary next action, with copy, restart, and navigation actions visibly secondary."]}
```

## PARSED_TASKS
- Validate OTPs server-side against the session’s issued challenge value; reject every non-matching six-digit value with a clear fix message.
- Record OTP challenge issuance time, expiry, used status, and failed-attempt count in the authenticated server session; expire or consume challenges so they cannot be reused.
- Rate-limit failed sign-in and OTP verification attempts server-side, applying a temporary lockout/cooldown and returning the remaining retry time in plain language.
- Generate a unique authenticator seed and recovery-code set for each enrolment with a cryptographically secure RNG; remove all hard-coded reusable secrets and codes.
- Encrypt each authenticator seed before retaining it server-side and retain only cryptographic hashes of recovery codes; return each plaintext recovery-code set only at generation time.
- Enforce server-side session idle and absolute expiry using created and last-seen timestamps, deleting expired sessions before authorizing requests.
- Implement a pre-authentication CSRF token flow and require its validation on sign-in; continue requiring session-bound CSRF validation for every authenticated state-changing request.
- Strictly validate JSON body shapes and server-side email, password, and OTP types, lengths, and formats before authentication or MFA processing.
- Provide recovery-code saving controls for copy-all and download or print, with clipboard fallback and a plain confirmation after the user saves them.
- Add a clearly labeled demo/testing mode that logs mock OTP and returned recovery codes with browser console.log only when enabled; keep secret logging absent in normal operation.
- Provide secondary setup controls to reveal or hide the authenticator secret, copy the secret and provisioning URI, restart provisioning, and return from verification to setup without penalty.
- Add a short contextual help or hint at every flow step and remove the persistent on-page diagnostic log from the standard user interface.
- Add an authenticated session-status/settings endpoint and initialize the client from it so a refreshed page restores the signed-in user’s correct MFA enrolment step.
- Make each setup and recovery screen have one visually dominant primary next action, with copy, restart, and navigation actions visibly secondary.