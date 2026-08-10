# TASKER REPORT — Iteration 5 · Step 13

## SUMMARY
- Raw tasks from Tasker: 4
- Effective task_list after retention: 4
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Replace `qrCanvas()` with a local standards-compliant QR encoder that renders a valid, scannable QR code for the returned `otpauth://` provisioning URI, without external assets or network calls.","Make `/api/signin` return `academicMode` and `testMode`, and set both client values before rendering the identity step so simulated-only exposure is accurately labeled immediately after sign-in.","Verify the no-refresh academic identity flow: after sign-in and sending a code, log the returned simulated code in the browser console and render a “Reveal simulated code” control whenever academic mode is enabled.","Add a recovery-stage “Create new recovery codes” or “Replace recovery codes” action after codes exist; warn that it replaces the old set, submit to the CSRF-protected `/api/recovery/create` endpoint, then re-render and browser-console-log the newly issued mock codes in test mode."]}
```

## PARSED_TASKS
- Replace qrCanvas() with a local standards-compliant QR encoder that renders a valid, scannable QR code for the returned otpauth:// provisioning URI, without external assets or network calls.
- Make /api/signin return academicMode and testMode, and set both client values before rendering the identity step so simulated-only exposure is accurately labeled immediately after sign-in.
- Verify the no-refresh academic identity flow: after sign-in and sending a code, log the returned simulated code in the browser console and render a “Reveal simulated code” control whenever academic mode is enabled.
- Add a recovery-stage “Create new recovery codes” or “Replace recovery codes” action after codes exist; warn that it replaces the old set, submit to the CSRF-protected /api/recovery/create endpoint, then re-render and browser-console-log the newly issued mock codes in test mode.