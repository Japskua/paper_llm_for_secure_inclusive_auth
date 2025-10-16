# TASKER REPORT — Iteration 2 · Step 4

## SUMMARY
- Tasks produced: 7
- Done: False

## RAW_OUTPUT
```
{
  "task_list": [
    "Add a visible status region near the top of <main>: <div id=\"global-status-visible\" class=\"status\" role=\"status\" aria-live=\"polite\" hidden></div>.",
    "Add inline CSS styles for .status (and optional .status--info/.status--success/.status--error) to make messages noticeable and non-intrusive.",
    "Update setGlobalStatus(msg, type='info') to update both #global-status (SR-only) and #global-status-visible, toggle hidden based on msg presence, and apply type-specific styles.",
    "In sendOrResendCode(), after logging the deterministic code, call setGlobalStatus('A 6-digit code was sent if the account exists.', 'info').",
    "On the \"Resend code\" action, call setGlobalStatus('Code resent. Check your messages. (In this demo, see the console.)', 'info').",
    "On init, when restoring and landing on Step 2, call setGlobalStatus('Resuming: Enter the 6-digit code. You can resend if needed.', 'info').",
    "Optionally, before navigating from Step 2 to Step 3 on successful code entry, call setGlobalStatus('Code accepted. Next: create a new password.', 'success')."
  ],
  "done": false
}
```

## PARSED_TASKS
- Add a visible status region near the top of <main>: <div id="global-status-visible" class="status" role="status" aria-live="polite" hidden></div>.
- Add inline CSS styles for .status (and optional .status--info/.status--success/.status--error) to make messages noticeable and non-intrusive.
- Update setGlobalStatus(msg, type='info') to update both #global-status (SR-only) and #global-status-visible, toggle hidden based on msg presence, and apply type-specific styles.
- In sendOrResendCode(), after logging the deterministic code, call setGlobalStatus('A 6-digit code was sent if the account exists.', 'info').
- On the "Resend code" action, call setGlobalStatus('Code resent. Check your messages. (In this demo, see the console.)', 'info').
- On init, when restoring and landing on Step 2, call setGlobalStatus('Resuming: Enter the 6-digit code. You can resend if needed.', 'info').
- Optionally, before navigating from Step 2 to Step 3 on successful code entry, call setGlobalStatus('Code accepted. Next: create a new password.', 'success').