# TASKER REPORT — Iteration 6 · Step 16

## SUMMARY
- Raw tasks from Tasker: 6
- Effective task_list after retention: 6
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Replace fakeQr() with an in-browser standards-compliant QR encoder that encodes the returned otpauth:// provisioning URI and produces a scanner-readable QR code without external assets or network calls.","Add an authenticator OTP expiry timestamp to the authenticated session when provisioning occurs, and reject authenticator verification after expiry with a clear message directing the user to provision again.","Keep identity-verification failure counts and lockout state when a replacement identity code is requested, and throttle code requests so requesting another code cannot bypass the failed-attempt lockout.","Do not clear authenticator OTP failure counts or lockout state through /api/mfa/provision while a lockout is active, and limit provisioning requests so reprovisioning cannot bypass MFA verification protections.","Generate a cryptographically random authenticator secret for every provisioning event and generate cryptographically random recovery codes for every initial generation or regeneration; store recovery-code hashes with unique random salts and return academic mock values only to the authenticated UI/browser console.","Include the account MFA-enabled status in bootstrap/session routing, route identity-confirmed users with unfinished MFA back to authenticator setup after refresh, and show active MFA settings only after MFA has been enabled."]}
```

## PARSED_TASKS
- Replace fakeQr() with an in-browser standards-compliant QR encoder that encodes the returned otpauth:// provisioning URI and produces a scanner-readable QR code without external assets or network calls.
- Add an authenticator OTP expiry timestamp to the authenticated session when provisioning occurs, and reject authenticator verification after expiry with a clear message directing the user to provision again.
- Keep identity-verification failure counts and lockout state when a replacement identity code is requested, and throttle code requests so requesting another code cannot bypass the failed-attempt lockout.
- Do not clear authenticator OTP failure counts or lockout state through /api/mfa/provision while a lockout is active, and limit provisioning requests so reprovisioning cannot bypass MFA verification protections.
- Generate a cryptographically random authenticator secret for every provisioning event and generate cryptographically random recovery codes for every initial generation or regeneration; store recovery-code hashes with unique random salts and return academic mock values only to the authenticated UI/browser console.
- Include the account MFA-enabled status in bootstrap/session routing, route identity-confirmed users with unfinished MFA back to authenticator setup after refresh, and show active MFA settings only after MFA has been enabled.