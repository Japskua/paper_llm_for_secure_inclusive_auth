# TASKER REPORT — Iteration 3 · Step 7

## SUMMARY
- Raw tasks from Tasker: 8
- Effective task_list after retention: 8
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Replace the shared hard-coded account session model with a server-side account record keyed by an authenticated user identity; reject sign-in attempts for identities other than the configured mock account, or implement a mock authentication check that binds the session to the submitted account.","Scope MFA state, OTP seed, verification attempts, lockouts, recovery-code hashes, and MFA status to session.userId rather than a single global user object.","Generate a new Base32-compatible OTP shared secret with crypto.getRandomValues() for each authorised authenticator enrolment; retain deterministic mock verification behavior separately if required for testing.","Prevent accepted TOTP steps from being reset by ordinary provisioning requests; preserve used-step history, or require an explicit authenticated MFA-reset/replacement flow before replacing an existing authenticator.","Add per-account recovery-code failure counters, a bounded attempt window, and lockout/rate-limit responses to /api/recovery/verify.","Replace trustedOrigin() with an exact allow-list of supported origins, including https://localhost:3000, https://127.0.0.1:3000, and https://[::1]:3000; use that same allow-list for CORS and CSRF origin validation.","Remove the persistent visible #logs panel or redact sensitive values from it; retain required mock delivery values in browser console.log only.","Add hide/reveal controls for the provisioning URI and manual secret, with the secret hidden by default after initial setup display while retaining copy functionality."]}
```

## PARSED_TASKS
- Replace the shared hard-coded account session model with a server-side account record keyed by an authenticated user identity; reject sign-in attempts for identities other than the configured mock account, or implement a mock authentication check that binds the session to the submitted account.
- Scope MFA state, OTP seed, verification attempts, lockouts, recovery-code hashes, and MFA status to session.userId rather than a single global user object.
- Generate a new Base32-compatible OTP shared secret with crypto.getRandomValues() for each authorised authenticator enrolment; retain deterministic mock verification behavior separately if required for testing.
- Prevent accepted TOTP steps from being reset by ordinary provisioning requests; preserve used-step history, or require an explicit authenticated MFA-reset/replacement flow before replacing an existing authenticator.
- Add per-account recovery-code failure counters, a bounded attempt window, and lockout/rate-limit responses to /api/recovery/verify.
- Replace trustedOrigin() with an exact allow-list of supported origins, including https://localhost:3000, https://127.0.0.1:3000, and https://[::1]:3000; use that same allow-list for CORS and CSRF origin validation.
- Remove the persistent visible #logs panel or redact sensitive values from it; retain required mock delivery values in browser console.log only.
- Add hide/reveal controls for the provisioning URI and manual secret, with the secret hidden by default after initial setup display while retaining copy functionality.