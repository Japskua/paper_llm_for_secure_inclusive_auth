# TASKER REPORT — Iteration 7 · Step 19

## SUMMARY
- Raw tasks from Tasker: 8
- Effective task_list after retention: 8
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Replace the custom QR rendering with a self-contained, standards-compliant QR encoder for the provisioning URI, including error correction, block interleaving, masking, and metadata so standard authenticator scanners can read it.","Add accessible copy controls for the provisioning URI, manual authenticator key, and displayed recovery-code set; show a plain visible confirmation after a successful copy.","Before validating an authenticator OTP, enforce the authenticator lockout guard; reset that guard after successful authenticator verification.","Before validating a recovery code, enforce the recovery lockout guard; reset that guard after successful recovery-code verification.","Ensure every regenerated mock recovery-code set is distinct from all earlier issued sets, so a code that was previously consumed can never become valid again.","Handle API failures in the recovery acknowledgement and recovery-code regeneration actions, displaying the server-provided actionable error message in the UI.","Add accessible hide/reveal controls for authenticator setup details and a re-request control that invalidates prior pending setup details when replacement details are issued.","After identity-code or authenticator-detail requests, present re-requesting only as a secondary control and keep verification or continuation as the sole primary action."]}
```

## PARSED_TASKS
- Replace the custom QR rendering with a self-contained, standards-compliant QR encoder for the provisioning URI, including error correction, block interleaving, masking, and metadata so standard authenticator scanners can read it.
- Add accessible copy controls for the provisioning URI, manual authenticator key, and displayed recovery-code set; show a plain visible confirmation after a successful copy.
- Before validating an authenticator OTP, enforce the authenticator lockout guard; reset that guard after successful authenticator verification.
- Before validating a recovery code, enforce the recovery lockout guard; reset that guard after successful recovery-code verification.
- Ensure every regenerated mock recovery-code set is distinct from all earlier issued sets, so a code that was previously consumed can never become valid again.
- Handle API failures in the recovery acknowledgement and recovery-code regeneration actions, displaying the server-provided actionable error message in the UI.
- Add accessible hide/reveal controls for authenticator setup details and a re-request control that invalidates prior pending setup details when replacement details are issued.
- After identity-code or authenticator-detail requests, present re-requesting only as a secondary control and keep verification or continuation as the sole primary action.