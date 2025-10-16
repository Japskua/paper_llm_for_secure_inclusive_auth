# TASKER REPORT — Iteration 1 · Step 1

## SUMMARY
- Tasks produced: 26
- Done: False

## RAW_OUTPUT
```
{
  "task_list": [
    "Create a single index.html file using semantic HTML with inline CSS and JS, including top-level comments mapping sections to the spec.",
    "Add a clear page title and short intro that outlines the step-by-step password recovery flow.",
    "Implement a visible progress indicator showing steps (Identify, Verify, New Password, Done) that updates as the user advances.",
    "Build Step 1 UI to collect email or username with concise instructions and a primary Continue action.",
    "On Step 1 submission, simulate sending a deterministic verification code via console.log and record progress in local storage.",
    "Display confirmation after Step 1 that a code was sent without indicating whether the account exists.",
    "Build Step 2 UI to enter the verification code with clear labeling and brief guidance.",
    "Add a Resend Code action that logs the same deterministic code again without timers or limits.",
    "Validate the entered verification code deterministically and show clear, inline success or error feedback.",
    "Build Step 3 UI to create a new password with show/hide toggles and a confirm password field.",
    "Provide simple, plain-language password guidance and inline validation for match and minimum rules.",
    "On successful password submission, advance to Step 4 and clear sensitive inputs from memory and UI.",
    "Build Step 4 confirmation UI with next-step guidance and a button to restart the flow.",
    "Persist current step and key inputs in local storage so users can pause and resume.",
    "Restore persisted state on load and move focus to the current step heading.",
    "Use high-contrast, low-distraction styling with generous spacing and large tap targets.",
    "Write microcopy that is concise, consistent, and ADHD-friendly across all steps.",
    "Provide a Help option available on every step with brief tips and contact placeholders.",
    "Include Back and Cancel controls that allow navigation without losing context and never auto-advance.",
    "Add ARIA roles, labels, and live regions for progress and validation messages.",
    "Manage focus on step changes to the step heading and prevent disorienting scroll jumps.",
    "Ensure the flow runs entirely client-side with no network calls and remains a single file.",
    "Add a Start Over action that confirms, clears local storage, and returns to Step 1.",
    "Insert inline comments in HTML/CSS/JS linking each part to inclusivity and mocking requirements.",
    "Create a brief testing checklist as comments and manually verify happy path and error cases.",
    "Ensure all controls are keyboard-accessible and follow a logical tab order without traps."
  ],
  "done": false
}
```

## PARSED_TASKS
- Create a single index.html file using semantic HTML with inline CSS and JS, including top-level comments mapping sections to the spec.
- Add a clear page title and short intro that outlines the step-by-step password recovery flow.
- Implement a visible progress indicator showing steps (Identify, Verify, New Password, Done) that updates as the user advances.
- Build Step 1 UI to collect email or username with concise instructions and a primary Continue action.
- On Step 1 submission, simulate sending a deterministic verification code via console.log and record progress in local storage.
- Display confirmation after Step 1 that a code was sent without indicating whether the account exists.
- Build Step 2 UI to enter the verification code with clear labeling and brief guidance.
- Add a Resend Code action that logs the same deterministic code again without timers or limits.
- Validate the entered verification code deterministically and show clear, inline success or error feedback.
- Build Step 3 UI to create a new password with show/hide toggles and a confirm password field.
- Provide simple, plain-language password guidance and inline validation for match and minimum rules.
- On successful password submission, advance to Step 4 and clear sensitive inputs from memory and UI.
- Build Step 4 confirmation UI with next-step guidance and a button to restart the flow.
- Persist current step and key inputs in local storage so users can pause and resume.
- Restore persisted state on load and move focus to the current step heading.
- Use high-contrast, low-distraction styling with generous spacing and large tap targets.
- Write microcopy that is concise, consistent, and ADHD-friendly across all steps.
- Provide a Help option available on every step with brief tips and contact placeholders.
- Include Back and Cancel controls that allow navigation without losing context and never auto-advance.
- Add ARIA roles, labels, and live regions for progress and validation messages.
- Manage focus on step changes to the step heading and prevent disorienting scroll jumps.
- Ensure the flow runs entirely client-side with no network calls and remains a single file.
- Add a Start Over action that confirms, clears local storage, and returns to Step 1.
- Insert inline comments in HTML/CSS/JS linking each part to inclusivity and mocking requirements.
- Create a brief testing checklist as comments and manually verify happy path and error cases.
- Ensure all controls are keyboard-accessible and follow a logical tab order without traps.