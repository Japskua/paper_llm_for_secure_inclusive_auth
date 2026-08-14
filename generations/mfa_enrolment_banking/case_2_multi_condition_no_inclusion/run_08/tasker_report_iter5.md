# TASKER REPORT — Iteration 5 · Step 13

## SUMMARY
- Raw tasks from Tasker: 4
- Effective task_list after retention: 4
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Update `/api/signin` so every syntactically valid credential attempt performs equivalent password-hash work before returning, regardless of whether the submitted email matches an account; ensure failure timing does not disclose account existence.","Change failed-login tracking so arbitrary email submissions cannot increment and lock the Marcus account. Track failures for the matched account only, while applying a separate generic/session/IP-oriented throttle for unknown principals if needed.","Serialize or atomically reserve recovery-code regeneration per account/session so only one regeneration operation can succeed at a time and every returned code set remains the currently active set.","Remove the persistent in-page sensitive-value transcript, or clear/redact provisioning secrets, OTPs, and recovery codes when progressing away from their relevant step. Keep the required mock output in the browser developer console via `console.log`, and show recovery codes only on the dedicated recovery-code screen."]}
```

## PARSED_TASKS
- Update /api/signin so every syntactically valid credential attempt performs equivalent password-hash work before returning, regardless of whether the submitted email matches an account; ensure failure timing does not disclose account existence.
- Change failed-login tracking so arbitrary email submissions cannot increment and lock the Marcus account. Track failures for the matched account only, while applying a separate generic/session/IP-oriented throttle for unknown principals if needed.
- Serialize or atomically reserve recovery-code regeneration per account/session so only one regeneration operation can succeed at a time and every returned code set remains the currently active set.
- Remove the persistent in-page sensitive-value transcript, or clear/redact provisioning secrets, OTPs, and recovery codes when progressing away from their relevant step. Keep the required mock output in the browser developer console via console.log, and show recovery codes only on the dedicated recovery-code screen.