# TASKER REPORT — Iteration 9 · Step 25

## SUMMARY
- Raw tasks from Tasker: 14
- Effective task_list after retention: 14
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Enforce the identity-code lockout on `/api/identity/verify`: reject every verification attempt until `identityLockedUntil` has passed, including correct codes.","Enforce the authenticator-code lockout on `/api/authenticator/verify` and prevent `/api/authenticator/start` from resetting failures or issuing a new setup while `otpLockedUntil` is active.","Reset identity and authenticator failure counters or lock fields only after an expired lock and a legitimate newly issued code or setup attempt.","In test mode, use a fixed deterministic authenticator verification code and accept that fixture only in test mode; retain time-based cryptographic authenticator verification in production.","When recovery codes are generated in test mode, return them to the UI and emit them through browser `console.log` only; do not expose test fixtures in production.","Remove the visible debug-log panel and all DOM-based logging while retaining required simulated-flow output in the browser console.","Show the authenticator base32 secret as a clearly labeled manual setup value, separate from the provisioning URI, and provide a dedicated copy action.","Keep QR and provisioning-URI setup options with concise instructions, while allowing manual secret copying or entry without parsing a long URI.","Add a recovery-code copy action and show a plain visible confirmation after the codes are copied.","After initial recovery-code creation, provide a controlled regeneration action that clearly states old recovery codes will stop working and confirms successful replacement.","When authenticator setup details expire or authenticator verification is locked, show a clear user-facing error and an actionable “Show new setup details” or “Start again” control.","Handle backup-code generation failures before accessing returned codes, and render every API failure as a specific user-facing message without browser-side exceptions.","Show concise visible confirmation after sending a new identity code, displaying setup details, copying setup details, creating recovery codes, copying recovery codes, and regenerating recovery codes.","Maintain one visually prominent primary action per screen while presenting confirmations and retry controls without adding clutter."]}
```

## PARSED_TASKS
- Enforce the identity-code lockout on /api/identity/verify: reject every verification attempt until identityLockedUntil has passed, including correct codes.
- Enforce the authenticator-code lockout on /api/authenticator/verify and prevent /api/authenticator/start from resetting failures or issuing a new setup while otpLockedUntil is active.
- Reset identity and authenticator failure counters or lock fields only after an expired lock and a legitimate newly issued code or setup attempt.
- In test mode, use a fixed deterministic authenticator verification code and accept that fixture only in test mode; retain time-based cryptographic authenticator verification in production.
- When recovery codes are generated in test mode, return them to the UI and emit them through browser console.log only; do not expose test fixtures in production.
- Remove the visible debug-log panel and all DOM-based logging while retaining required simulated-flow output in the browser console.
- Show the authenticator base32 secret as a clearly labeled manual setup value, separate from the provisioning URI, and provide a dedicated copy action.
- Keep QR and provisioning-URI setup options with concise instructions, while allowing manual secret copying or entry without parsing a long URI.
- Add a recovery-code copy action and show a plain visible confirmation after the codes are copied.
- After initial recovery-code creation, provide a controlled regeneration action that clearly states old recovery codes will stop working and confirms successful replacement.
- When authenticator setup details expire or authenticator verification is locked, show a clear user-facing error and an actionable “Show new setup details” or “Start again” control.
- Handle backup-code generation failures before accessing returned codes, and render every API failure as a specific user-facing message without browser-side exceptions.
- Show concise visible confirmation after sending a new identity code, displaying setup details, copying setup details, creating recovery codes, copying recovery codes, and regenerating recovery codes.
- Maintain one visually prominent primary action per screen while presenting confirmations and retry controls without adding clutter.