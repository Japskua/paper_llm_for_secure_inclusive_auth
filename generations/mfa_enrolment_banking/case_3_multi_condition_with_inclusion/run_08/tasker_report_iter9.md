# TASKER REPORT — Iteration 9 · Step 25

## SUMMARY
- Raw tasks from Tasker: 6
- Effective task_list after retention: 6
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Make startup configuration explicit and runnable: document required key/pepper environment variables in code comments and provide a secure development-only generation path, or otherwise ensure the app can start under the required evaluation command without weakening production cryptography.","Replace `Bun.file(STORE_FILE).textSync()` with a valid Bun-compatible persistence read implementation, such as an asynchronous `await Bun.file(STORE_FILE).text()` initialization flow or a supported synchronous filesystem API; do not silently discard existing state on read errors.","Require `session.mfaVerified === true` for `/api/mfa/recovery/generate` and `/api/mfa/recovery/regenerate`, returning 403 with instructions to verify the authenticator or a recovery code first.","Preserve recovery codes in transient page memory when hidden and provide an explicit Reveal codes action; clear them only when leaving the relevant flow, ending the session, or replacing the code set.","Disable or hide Copy All while recovery codes are hidden so it cannot copy an empty value.","Remove the rendered in-page demo log panel while retaining required deterministic OTP and recovery-code output through browser `console.log`."]}
```

## PARSED_TASKS
- Make startup configuration explicit and runnable: document required key/pepper environment variables in code comments and provide a secure development-only generation path, or otherwise ensure the app can start under the required evaluation command without weakening production cryptography.
- Replace `Bun.file(STORE_FILE).textSync()` with a valid Bun-compatible persistence read implementation, such as an asynchronous `await Bun.file(STORE_FILE).text()` initialization flow or a supported synchronous filesystem API; do not silently discard existing state on read errors.
- Require session.mfaVerified === true for /api/mfa/recovery/generate and /api/mfa/recovery/regenerate, returning 403 with instructions to verify the authenticator or a recovery code first.
- Preserve recovery codes in transient page memory when hidden and provide an explicit Reveal codes action; clear them only when leaving the relevant flow, ending the session, or replacing the code set.
- Disable or hide Copy All while recovery codes are hidden so it cannot copy an empty value.
- Remove the rendered in-page demo log panel while retaining required deterministic OTP and recovery-code output through browser console.log.