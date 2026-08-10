# TASKER REPORT — Iteration 3 · Step 7

## SUMMARY
- Raw tasks from Tasker: 8
- Effective task_list after retention: 8
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Require a server-side mock authentication proof in addition to the email before assigning ACCOUNT_ID to a new session; reject callers without that proof while keeping the deterministic test login flow usable.",
    "Generate a fresh cryptographically random CSP nonce for each HTML response and use that same nonce in the CSP header and inline style/script nonce attributes.",
    "Fix the provisioning QR renderer so its data-bit array is initialized before any addBits call, and confirm opening the provisioning screen produces no browser console exception.",
    "Make the inline QR renderer standards-compliant for the generated otpauth URI, including version information, error correction, reserved modules, and masking; verify the rendered code is scannable by an authenticator.",
    "Record the accepted TOTP counter and reject reuse of a previously accepted counter; reset replay tracking whenever a new provisioning secret is created.",
    "Generate recovery codes with at least 64 bits of retained cryptographic entropy and display the complete generated value in the recovery-code format. Update server validation and client input constraints, examples, and help text to match the new format.",
    "Add concise code comments mapping authorization/IDOR, CSRF, headers, session controls, encrypted OTP storage, recovery-code hashing, validation/XSS protection, verification expiry/replay prevention, and inclusive UI behavior to the corresponding requirements.",
    "Test the complete browser flow: authenticated sign-in, identity-code request and verification, QR/manual authenticator setup, TOTP verification, recovery-code generation and copy, completion, and one-time recovery-code verification."
  ]
}
```

## PARSED_TASKS
- Require a server-side mock authentication proof in addition to the email before assigning ACCOUNT_ID to a new session; reject callers without that proof while keeping the deterministic test login flow usable.
- Generate a fresh cryptographically random CSP nonce for each HTML response and use that same nonce in the CSP header and inline style/script nonce attributes.
- Fix the provisioning QR renderer so its data-bit array is initialized before any addBits call, and confirm opening the provisioning screen produces no browser console exception.
- Make the inline QR renderer standards-compliant for the generated otpauth URI, including version information, error correction, reserved modules, and masking; verify the rendered code is scannable by an authenticator.
- Record the accepted TOTP counter and reject reuse of a previously accepted counter; reset replay tracking whenever a new provisioning secret is created.
- Generate recovery codes with at least 64 bits of retained cryptographic entropy and display the complete generated value in the recovery-code format. Update server validation and client input constraints, examples, and help text to match the new format.
- Add concise code comments mapping authorization/IDOR, CSRF, headers, session controls, encrypted OTP storage, recovery-code hashing, validation/XSS protection, verification expiry/replay prevention, and inclusive UI behavior to the corresponding requirements.
- Test the complete browser flow: authenticated sign-in, identity-code request and verification, QR/manual authenticator setup, TOTP verification, recovery-code generation and copy, completion, and one-time recovery-code verification.