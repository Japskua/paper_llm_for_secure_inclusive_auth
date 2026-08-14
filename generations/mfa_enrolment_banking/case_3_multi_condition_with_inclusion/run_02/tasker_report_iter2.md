# TASKER REPORT — Iteration 2 · Step 4

## SUMMARY
- Raw tasks from Tasker: 10
- Effective task_list after retention: 10
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Replace the pseudo-QR canvas with an inline, standards-compliant QR encoder that encodes the authenticated user's `otpauth://totp/...` provisioning URI and is scannable by authenticator applications without external assets.","Implement RFC 6238 server-side TOTP generation and verification from the encrypted provisioned secret, accepting a small clock-skew window and returning plain retry guidance for invalid codes.","Create an explicitly isolated evaluator/demo mode for deterministic mock identity OTPs, TOTP fixtures, and recovery codes; keep normal mode cryptographically random and ensure production mode never logs or displays secrets outside their intended protected UI.","Remove the visible in-page secret log panel and ensure production browser/server logs never contain OTP seeds, OTPs, recovery codes, or session tokens.","Preserve pending authenticator enrolment server-side and provide an authenticated, CSRF-protected endpoint that returns the existing provisioning state without generating or replacing its secret.","Update client state restoration so a refresh in pending setup re-renders the existing setup and a refresh in the `backup` state re-renders the recovery-code acknowledgement step.","Show the setup secret and full provisioning URI in the setup UI through clear reveal/hide and copy controls, so manual authenticator provisioning works without clipboard access or QR scanning.","Add an authenticated, CSRF-protected recovery-code regeneration action that invalidates the prior set, issues a replacement set, and plainly confirms that the old codes no longer work.","Hash each recovery code with a unique salt using a deliberately slow KDF such as PBKDF2, scrypt, or Argon2, and verify submitted codes against that stored KDF output.","Add a protected post-enrolment MFA verification endpoint and UI that accepts a current TOTP or consumes one single-use recovery code, with validation, rate limiting, and temporary lockout on repeated failures."]}
```

## PARSED_TASKS
- Replace the pseudo-QR canvas with an inline, standards-compliant QR encoder that encodes the authenticated user's otpauth://totp/... provisioning URI and is scannable by authenticator applications without external assets.
- Implement RFC 6238 server-side TOTP generation and verification from the encrypted provisioned secret, accepting a small clock-skew window and returning plain retry guidance for invalid codes.
- Create an explicitly isolated evaluator/demo mode for deterministic mock identity OTPs, TOTP fixtures, and recovery codes; keep normal mode cryptographically random and ensure production mode never logs or displays secrets outside their intended protected UI.
- Remove the visible in-page secret log panel and ensure production browser/server logs never contain OTP seeds, OTPs, recovery codes, or session tokens.
- Preserve pending authenticator enrolment server-side and provide an authenticated, CSRF-protected endpoint that returns the existing provisioning state without generating or replacing its secret.
- Update client state restoration so a refresh in pending setup re-renders the existing setup and a refresh in the backup state re-renders the recovery-code acknowledgement step.
- Show the setup secret and full provisioning URI in the setup UI through clear reveal/hide and copy controls, so manual authenticator provisioning works without clipboard access or QR scanning.
- Add an authenticated, CSRF-protected recovery-code regeneration action that invalidates the prior set, issues a replacement set, and plainly confirms that the old codes no longer work.
- Hash each recovery code with a unique salt using a deliberately slow KDF such as PBKDF2, scrypt, or Argon2, and verify submitted codes against that stored KDF output.
- Add a protected post-enrolment MFA verification endpoint and UI that accepts a current TOTP or consumes one single-use recovery code, with validation, rate limiting, and temporary lockout on repeated failures.