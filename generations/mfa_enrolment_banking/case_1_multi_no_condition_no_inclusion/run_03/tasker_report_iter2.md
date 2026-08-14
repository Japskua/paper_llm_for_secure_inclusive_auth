# TASKER REPORT — Iteration 2 · Step 4

## SUMMARY
- Raw tasks from Tasker: 8
- Effective task_list after retention: 8
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Replace the independent provisioning verification code with a simulated TOTP flow derived from the provisioned secret, with a defined time step and deterministic test clock/code fixture; retain manual secret setup.","Define deterministic browser-visible fixtures for simulated identity-code and authenticator-code delivery while using cryptographically secure generation for stored production-sensitive secrets and recovery codes, or isolate an explicit non-production test mode.","Restrict mock sign-in to the configured simulated Marcus email and phone identity, and establish the account identity exclusively from server-side configuration rather than client-supplied identifiers.","Track invalid identity-code attempts in server-side account or challenge state, apply throttling and a temporary lockout after a defined failure threshold, and return generic responses.","Store MFA TOTP and recovery-code verification failure counters and lockout state in server-side account or challenge records so a new session cannot bypass an active lockout.","After successful identity verification, invalidate the pre-verification session, create a replacement authenticated session, set its secure `mfa_session` cookie, and return its replacement CSRF token.","Replace bare SHA-256 recovery-code hashes with per-code salted KDF or keyed server-side verifiers, and remove the matched verifier after successful recovery-code use.","Make recovery-code acknowledgement reload-safe by either securely retaining pending plaintext codes only for the active authenticated enrolment flow or requiring regeneration before acknowledgement after reload, with clear UI guidance."]}
```

## PARSED_TASKS
- Replace the independent provisioning verification code with a simulated TOTP flow derived from the provisioned secret, with a defined time step and deterministic test clock/code fixture; retain manual secret setup.
- Define deterministic browser-visible fixtures for simulated identity-code and authenticator-code delivery while using cryptographically secure generation for stored production-sensitive secrets and recovery codes, or isolate an explicit non-production test mode.
- Restrict mock sign-in to the configured simulated Marcus email and phone identity, and establish the account identity exclusively from server-side configuration rather than client-supplied identifiers.
- Track invalid identity-code attempts in server-side account or challenge state, apply throttling and a temporary lockout after a defined failure threshold, and return generic responses.
- Store MFA TOTP and recovery-code verification failure counters and lockout state in server-side account or challenge records so a new session cannot bypass an active lockout.
- After successful identity verification, invalidate the pre-verification session, create a replacement authenticated session, set its secure `mfa_session` cookie, and return its replacement CSRF token.
- Replace bare SHA-256 recovery-code hashes with per-code salted KDF or keyed server-side verifiers, and remove the matched verifier after successful recovery-code use.
- Make recovery-code acknowledgement reload-safe by either securely retaining pending plaintext codes only for the active authenticated enrolment flow or requiring regeneration before acknowledgement after reload, with clear UI guidance.