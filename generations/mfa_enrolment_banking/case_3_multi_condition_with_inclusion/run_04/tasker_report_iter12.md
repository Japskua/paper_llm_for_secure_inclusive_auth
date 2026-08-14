# TASKER REPORT — Iteration 12 · Step 34

## SUMMARY
- Raw tasks from Tasker: 13
- Effective task_list after retention: 13
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Enforce failed-attempt tracking and a ten-minute lockout for identity-code verification; clear expired locks before validation and reset identity failures when a new identity code is issued.","Enforce failed-attempt tracking and a ten-minute lockout for authenticator OTP verification; reject attempts while locked and reset failures after successful verification or newly issued setup details.","Enforce failed-attempt tracking and a ten-minute lockout for recovery-code verification; reject attempts while locked and reset failures after successful verification or regenerated recovery codes.","Generate identity verification codes with cryptographic randomness in production, store only the data needed for secure time-bound single-use validation, and retain deterministic codes only in explicitly isolated test mode.","Validate production authenticator OTP entries as time-based OTPs derived from the enrolled decrypted authenticator secret, while retaining deterministic authenticator behavior only in explicitly isolated test mode.","Correct the in-file Version 8 QR encoder to write required version-information BCH modules so provisioning QR symbols are standards-compliant and scannable.","Add an identity-verification UI action to send a new code, call the protected resend route, and show a plain-language confirmation and next step.","Add an authenticator-details UI action to request new setup details and show a plain-language confirmation of the replacement setup information.","Add a recovery-code regeneration UI action that calls the protected regeneration route and clearly explains that prior recovery codes no longer work.","Add recovery-code hide and reveal controls so displayed codes can be concealed and re-displayed during enrolment without re-entry.","Await clipboard copy attempts and display a clear success confirmation or a plain-language fallback message when clipboard access is unavailable.","Provide a consistent, brief, easy-to-find help or hint affordance on every enrolment step.","Add clear code comments mapping server security controls and client accessibility behavior to the corresponding stated requirement sections."]}
```

## PARSED_TASKS
- Enforce failed-attempt tracking and a ten-minute lockout for identity-code verification; clear expired locks before validation and reset identity failures when a new identity code is issued.
- Enforce failed-attempt tracking and a ten-minute lockout for authenticator OTP verification; reject attempts while locked and reset failures after successful verification or newly issued setup details.
- Enforce failed-attempt tracking and a ten-minute lockout for recovery-code verification; reject attempts while locked and reset failures after successful verification or regenerated recovery codes.
- Generate identity verification codes with cryptographic randomness in production, store only the data needed for secure time-bound single-use validation, and retain deterministic codes only in explicitly isolated test mode.
- Validate production authenticator OTP entries as time-based OTPs derived from the enrolled decrypted authenticator secret, while retaining deterministic authenticator behavior only in explicitly isolated test mode.
- Correct the in-file Version 8 QR encoder to write required version-information BCH modules so provisioning QR symbols are standards-compliant and scannable.
- Add an identity-verification UI action to send a new code, call the protected resend route, and show a plain-language confirmation and next step.
- Add an authenticator-details UI action to request new setup details and show a plain-language confirmation of the replacement setup information.
- Add a recovery-code regeneration UI action that calls the protected regeneration route and clearly explains that prior recovery codes no longer work.
- Add recovery-code hide and reveal controls so displayed codes can be concealed and re-displayed during enrolment without re-entry.
- Await clipboard copy attempts and display a clear success confirmation or a plain-language fallback message when clipboard access is unavailable.
- Provide a consistent, brief, easy-to-find help or hint affordance on every enrolment step.
- Add clear code comments mapping server security controls and client accessibility behavior to the corresponding stated requirement sections.