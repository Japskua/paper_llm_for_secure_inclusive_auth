# TASKER REPORT — Iteration 1 · Step 1

## SUMMARY
- Raw tasks from Tasker: 23
- Effective task_list after retention: 23
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Create index.html with semantic sections (header, main, footer) and commented blocks mapping to spec headings. Acceptance: file loads standalone with visible headings and comments referencing requirements.",
    "Add inline CSS for readable defaults (large base font, high contrast, spacious line-height and spacing, no italics/all-caps). Acceptance: body text ≥16px, line-height ≥1.5, dark text on light background.",
    "Add clear focus outlines and ensure all interactive elements are keyboard navigable. Acceptance: Tabbing reveals visible focus on links, buttons, and inputs.",
    "Add a visible deadline banner showing time left until local midnight and update it every second. Acceptance: banner counts down live and remains readable.",
    "Add a global Read Aloud button to speak current step instructions, with a fallback Copy Text button if speech is unavailable. Acceptance: click reads or copies the visible instruction text.",
    "Add a clear page title and a simple step indicator with short bullet-point instructions. Acceptance: current step is labeled and instructions are ≤5 short bullets.",
    "Build the Email step form with labeled email input and a Send code button. Acceptance: submitting with a non-empty email advances to the Code step.",
    "Generate a deterministic 6-digit recovery code from the entered email and log it via console.log. Acceptance: the same email always produces the same code and a console message shows it.",
    "Add an ARIA live region for status messages (polite). Acceptance: success/error text is announced by screen readers without shifting focus.",
    "Build the Code step with a single 6-digit input, a Verify button, and a Resend button. Acceptance: Resend logs a new console message with the same deterministic code.",
    "On incorrect code, show a short error and keep focus in the code field without lockout. Acceptance: multiple wrong attempts are allowed and error text is concise.",
    "Build the Reset Password step with New password and Confirm fields and show/hide toggles. Acceptance: toggles reveal/hide input text and both fields are labeled.",
    "Display a plain-language checklist that updates live as password rules are met. Acceptance: each rule shows a clear pass/fail indicator that updates on typing.",
    "On valid and matching passwords, advance to Login and log a console message indicating password reset. Acceptance: mismatch or unmet rules show a short fix-it message.",
    "Build the Login step prefilled with the entered email and a password field. Acceptance: entering the new password logs in and advances to the Course page.",
    "Create a simple Course page with a clear heading, a course card, and an Upload assignment control. Acceptance: a file input and Upload button are visible and labeled.",
    "Simulate upload by showing a success message with filename and timestamp (no network). Acceptance: selecting a file and clicking Upload displays the filename and time.",
    "Add Back and Start over buttons on each step with predictable navigation. Acceptance: Back returns to the previous step and Start over resets to the Email step while preserving readability settings.",
    "Ensure all controls have explicit labels, accessible names, and helpful hints (no long text). Acceptance: label-for associations exist and inputs have short helper text.",
    "Add a Readable mode toggle that increases font size, letter/word spacing, and line-height. Acceptance: toggling visibly adjusts text spacing and size across the page.",
    "Use concise, plain-language copy in short sentences or bullets throughout the UI. Acceptance: no paragraph exceeds 2 sentences and error messages are ≤1 sentence.",
    "Log key mock events to the console: code sent, verify attempts, password reset, login, and upload. Acceptance: each action produces a clear console.log entry.",
    "Implement minimal inline JS state management to switch steps without reloading and preserve email across steps. Acceptance: navigation happens in-place and the email persists from Email to Login."
  ]
}
```

## PARSED_TASKS
- Create index.html with semantic sections (header, main, footer) and commented blocks mapping to spec headings. Acceptance: file loads standalone with visible headings and comments referencing requirements.
- Add inline CSS for readable defaults (large base font, high contrast, spacious line-height and spacing, no italics/all-caps). Acceptance: body text ≥16px, line-height ≥1.5, dark text on light background.
- Add clear focus outlines and ensure all interactive elements are keyboard navigable. Acceptance: Tabbing reveals visible focus on links, buttons, and inputs.
- Add a visible deadline banner showing time left until local midnight and update it every second. Acceptance: banner counts down live and remains readable.
- Add a global Read Aloud button to speak current step instructions, with a fallback Copy Text button if speech is unavailable. Acceptance: click reads or copies the visible instruction text.
- Add a clear page title and a simple step indicator with short bullet-point instructions. Acceptance: current step is labeled and instructions are ≤5 short bullets.
- Build the Email step form with labeled email input and a Send code button. Acceptance: submitting with a non-empty email advances to the Code step.
- Generate a deterministic 6-digit recovery code from the entered email and log it via console.log. Acceptance: the same email always produces the same code and a console message shows it.
- Add an ARIA live region for status messages (polite). Acceptance: success/error text is announced by screen readers without shifting focus.
- Build the Code step with a single 6-digit input, a Verify button, and a Resend button. Acceptance: Resend logs a new console message with the same deterministic code.
- On incorrect code, show a short error and keep focus in the code field without lockout. Acceptance: multiple wrong attempts are allowed and error text is concise.
- Build the Reset Password step with New password and Confirm fields and show/hide toggles. Acceptance: toggles reveal/hide input text and both fields are labeled.
- Display a plain-language checklist that updates live as password rules are met. Acceptance: each rule shows a clear pass/fail indicator that updates on typing.
- On valid and matching passwords, advance to Login and log a console message indicating password reset. Acceptance: mismatch or unmet rules show a short fix-it message.
- Build the Login step prefilled with the entered email and a password field. Acceptance: entering the new password logs in and advances to the Course page.
- Create a simple Course page with a clear heading, a course card, and an Upload assignment control. Acceptance: a file input and Upload button are visible and labeled.
- Simulate upload by showing a success message with filename and timestamp (no network). Acceptance: selecting a file and clicking Upload displays the filename and time.
- Add Back and Start over buttons on each step with predictable navigation. Acceptance: Back returns to the previous step and Start over resets to the Email step while preserving readability settings.
- Ensure all controls have explicit labels, accessible names, and helpful hints (no long text). Acceptance: label-for associations exist and inputs have short helper text.
- Add a Readable mode toggle that increases font size, letter/word spacing, and line-height. Acceptance: toggling visibly adjusts text spacing and size across the page.
- Use concise, plain-language copy in short sentences or bullets throughout the UI. Acceptance: no paragraph exceeds 2 sentences and error messages are ≤1 sentence.
- Log key mock events to the console: code sent, verify attempts, password reset, login, and upload. Acceptance: each action produces a clear console.log entry.
- Implement minimal inline JS state management to switch steps without reloading and preserve email across steps. Acceptance: navigation happens in-place and the email persists from Email to Login.