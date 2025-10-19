# TASKER REPORT — Iteration 1 · Step 1

## SUMMARY
- Raw tasks from Tasker: 16
- Effective task_list after retention: 16
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Create index.html with semantic structure (header, main, footer) and inline CSS/JS placeholders.",
    "Insert top-of-file and section comments that map code areas to the spec (Purpose, Use-case, Deliverables, Mocking).",
    "Add an 'Identify account' form with username/email input and client-side validation (required, email pattern or min length).",
    "Define deterministic mock constants in JS (e.g., DEMO_USER and RECOVERY_CODE='123456').",
    "On valid identification submit, console.log a mocked delivery message with the deterministic code and show the code entry step.",
    "Implement a code verification form that accepts a 6-digit code, validates format, and compares against the deterministic code.",
    "Show an inline error on code mismatch and proceed to the next step on exact match.",
    "Add a 'Resend code' control that re-logs the same deterministic code to console and updates a status message.",
    "Create a password reset form with new password and confirm fields enforcing a strong policy (min 12 chars, upper, lower, number, symbol).",
    "Provide live criteria feedback and block submission until all criteria pass.",
    "Validate confirm password matches exactly and show an inline mismatch error.",
    "On successful reset, console.log a mocked success message and display a completion screen with a 'Start over' control.",
    "Implement focus management so focus moves to the first actionable element on each step change and errors are announced.",
    "Add aria-live regions for status and error messages to support screen readers.",
    "Write responsive, high-contrast inline CSS with large legible fonts, spacing, and visible focus outlines for accessibility.",
    "Ensure no external resources or network calls are used so the file runs fully offline in a fresh browser tab."
  ]
}
```

## PARSED_TASKS
- Create index.html with semantic structure (header, main, footer) and inline CSS/JS placeholders.
- Insert top-of-file and section comments that map code areas to the spec (Purpose, Use-case, Deliverables, Mocking).
- Add an 'Identify account' form with username/email input and client-side validation (required, email pattern or min length).
- Define deterministic mock constants in JS (e.g., DEMO_USER and RECOVERY_CODE='123456').
- On valid identification submit, console.log a mocked delivery message with the deterministic code and show the code entry step.
- Implement a code verification form that accepts a 6-digit code, validates format, and compares against the deterministic code.
- Show an inline error on code mismatch and proceed to the next step on exact match.
- Add a 'Resend code' control that re-logs the same deterministic code to console and updates a status message.
- Create a password reset form with new password and confirm fields enforcing a strong policy (min 12 chars, upper, lower, number, symbol).
- Provide live criteria feedback and block submission until all criteria pass.
- Validate confirm password matches exactly and show an inline mismatch error.
- On successful reset, console.log a mocked success message and display a completion screen with a 'Start over' control.
- Implement focus management so focus moves to the first actionable element on each step change and errors are announced.
- Add aria-live regions for status and error messages to support screen readers.
- Write responsive, high-contrast inline CSS with large legible fonts, spacing, and visible focus outlines for accessibility.
- Ensure no external resources or network calls are used so the file runs fully offline in a fresh browser tab.