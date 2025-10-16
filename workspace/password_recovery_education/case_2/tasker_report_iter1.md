# TASKER REPORT — Iteration 1 · Step 1

## SUMMARY
- Tasks produced: 18
- Done: False

## RAW_OUTPUT
```
{
  "task_list": [
    "Create index.html as a single self-contained file with semantic HTML structure.",
    "Add inline CSS for basic layout and readable typography; avoid external assets.",
    "Add inline JS only; do not perform any network requests.",
    "Implement Step 1: a 'Request password reset' form with labeled email/username input and submit.",
    "On submit, simulate sending a reset code via console.log using a fixed deterministic code.",
    "After sending, reveal Step 2: a 'Enter verification code' form with labeled input and submit.",
    "Validate the code strictly equals the deterministic mock value; show an inline error on mismatch and allow retry.",
    "Provide a 'Resend code' control that logs the same deterministic code again.",
    "On successful code verification, reveal Step 3: a 'Create new password' form with password and confirm fields.",
    "Enforce clear strong-password rules (e.g., minimum length and character variety) with real-time guidance text.",
    "Validate that password and confirmation match; show a specific inline error if they do not.",
    "On valid submission, display a success screen stating the password was reset and provide a mock 'Log in' action.",
    "Manage focus so the first field of each step is focused when that step becomes visible.",
    "Ensure all forms and messages use semantic elements and accessible labels; expose status updates accessibly.",
    "Add a 'Start over' control that returns the UI to Step 1 and clears state.",
    "Add comments in HTML/CSS/JS mapping each section to this spec (single page, mocked delivery, deterministic values, non-production).",
    "Log verification success and password reset events to console to simulate backend acknowledgement.",
    "Confirm the page works fully offline and without any build step."
  ],
  "done": false
}
```

## PARSED_TASKS
- Create index.html as a single self-contained file with semantic HTML structure.
- Add inline CSS for basic layout and readable typography; avoid external assets.
- Add inline JS only; do not perform any network requests.
- Implement Step 1: a 'Request password reset' form with labeled email/username input and submit.
- On submit, simulate sending a reset code via console.log using a fixed deterministic code.
- After sending, reveal Step 2: a 'Enter verification code' form with labeled input and submit.
- Validate the code strictly equals the deterministic mock value; show an inline error on mismatch and allow retry.
- Provide a 'Resend code' control that logs the same deterministic code again.
- On successful code verification, reveal Step 3: a 'Create new password' form with password and confirm fields.
- Enforce clear strong-password rules (e.g., minimum length and character variety) with real-time guidance text.
- Validate that password and confirmation match; show a specific inline error if they do not.
- On valid submission, display a success screen stating the password was reset and provide a mock 'Log in' action.
- Manage focus so the first field of each step is focused when that step becomes visible.
- Ensure all forms and messages use semantic elements and accessible labels; expose status updates accessibly.
- Add a 'Start over' control that returns the UI to Step 1 and clears state.
- Add comments in HTML/CSS/JS mapping each section to this spec (single page, mocked delivery, deterministic values, non-production).
- Log verification success and password reset events to console to simulate backend acknowledgement.
- Confirm the page works fully offline and without any build step.