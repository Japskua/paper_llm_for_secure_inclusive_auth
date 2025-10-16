# TASKER REPORT — Iteration 3 · Step 7

## SUMMARY
- Raw tasks from Tasker: 7
- Effective task_list after retention: 7
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Add appState.verified boolean (default false) to track whether the user has successfully verified the code.",
    "Set appState.verified = true only upon successful Step 2 code verification; keep it false on failed attempts.",
    "Gate navigation so Steps 3 and 4 require both an identifier and appState.verified = true in init/hash-change/step-setting; otherwise redirect to Step 2.",
    "Reset appState.verified to false on flow restart and whenever Step 2 is entered (e.g., via hash/back).",
    "Correct the #code input pattern to a valid six-digit regex or remove the attribute to avoid the double-escaped pattern.",
    "Update resend and mock delivery announcements to say \"Code resent.\" without implying a new code.",
    "For each Show/Hide password button, toggle aria-pressed to reflect visibility and keep the button label synchronized with the current state."
  ]
}
```

## PARSED_TASKS
- Add appState.verified boolean (default false) to track whether the user has successfully verified the code.
- Set appState.verified = true only upon successful Step 2 code verification; keep it false on failed attempts.
- Gate navigation so Steps 3 and 4 require both an identifier and appState.verified = true in init/hash-change/step-setting; otherwise redirect to Step 2.
- Reset appState.verified to false on flow restart and whenever Step 2 is entered (e.g., via hash/back).
- Correct the #code input pattern to a valid six-digit regex or remove the attribute to avoid the double-escaped pattern.
- Update resend and mock delivery announcements to say "Code resent." without implying a new code.
- For each Show/Hide password button, toggle aria-pressed to reflect visibility and keep the button label synchronized with the current state.