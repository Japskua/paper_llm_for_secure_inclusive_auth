# TASKER REPORT — Iteration 1 · Step 1

## SUMMARY
- Raw tasks from Tasker: 20
- Effective task_list after retention: 20
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Create index.html as a single self-contained file with semantic HTML, inline CSS/JS scaffolding, and top-level comments mapping to the spec.",
    "Add a four-step recovery flow (Identify, Verify Code, New Password, Done) with a visible progress indicator showing 1/4 to 4/4.",
    "Implement Step 1 form to collect username or email with clear instructions, inline validation, and disabled Continue until valid.",
    "On Step 1 Continue, simulate sending a recovery code by console.logging a fixed deterministic code (e.g., 246810) and advance to Step 2 with feedback.",
    "Provide a Resend Code action on Step 2 that re-logs the same deterministic code to the console and confirms resend without timers.",
    "Implement Step 2 input for a 6-digit code; validate against the fixed code and show inline error on mismatch, proceed on match.",
    "Implement Step 3 new password form with strength indicator, confirmation field, and plain-language rules; block weak or mismatched passwords.",
    "Implement Step 4 success screen with confirmation, next-step guidance, and buttons to restart or go to a placeholder login.",
    "Persist current step and inputs locally so reloading restores the user to the last step with prior values.",
    "Add a Save and return later action on all steps that saves state and shows a reassuring, non-timed confirmation.",
    "Add a contextual Help panel accessible from every step with brief guidance and a contact placeholder; ensure keyboard accessibility.",
    "Apply clear, high-contrast, low-clutter styling with large readable text and visible focus outlines meeting WCAG AA contrast.",
    "Add ARIA roles and an aria-live region so success and error messages are announced to assistive technologies.",
    "Include Back buttons to return to the previous step without losing entered data.",
    "Add a Start over control that clears saved progress and returns to Step 1.",
    "Ensure there are no time-based behaviors (no timeouts or code expiry) to avoid pressure.",
    "Insert inline comments linking code sections to inclusivity, mocking, and deliverables requirements.",
    "Verify the app runs fully offline with no network requests and that delivery/verification use console.log and the fixed code.",
    "Implement keyboard navigation support including a skip-to-content link and logical tab order.",
    "Add a brief manual test checklist as HTML comments at the end of the file."
  ]
}
```

## PARSED_TASKS
- Create index.html as a single self-contained file with semantic HTML, inline CSS/JS scaffolding, and top-level comments mapping to the spec.
- Add a four-step recovery flow (Identify, Verify Code, New Password, Done) with a visible progress indicator showing 1/4 to 4/4.
- Implement Step 1 form to collect username or email with clear instructions, inline validation, and disabled Continue until valid.
- On Step 1 Continue, simulate sending a recovery code by console.logging a fixed deterministic code (e.g., 246810) and advance to Step 2 with feedback.
- Provide a Resend Code action on Step 2 that re-logs the same deterministic code to the console and confirms resend without timers.
- Implement Step 2 input for a 6-digit code; validate against the fixed code and show inline error on mismatch, proceed on match.
- Implement Step 3 new password form with strength indicator, confirmation field, and plain-language rules; block weak or mismatched passwords.
- Implement Step 4 success screen with confirmation, next-step guidance, and buttons to restart or go to a placeholder login.
- Persist current step and inputs locally so reloading restores the user to the last step with prior values.
- Add a Save and return later action on all steps that saves state and shows a reassuring, non-timed confirmation.
- Add a contextual Help panel accessible from every step with brief guidance and a contact placeholder; ensure keyboard accessibility.
- Apply clear, high-contrast, low-clutter styling with large readable text and visible focus outlines meeting WCAG AA contrast.
- Add ARIA roles and an aria-live region so success and error messages are announced to assistive technologies.
- Include Back buttons to return to the previous step without losing entered data.
- Add a Start over control that clears saved progress and returns to Step 1.
- Ensure there are no time-based behaviors (no timeouts or code expiry) to avoid pressure.
- Insert inline comments linking code sections to inclusivity, mocking, and deliverables requirements.
- Verify the app runs fully offline with no network requests and that delivery/verification use console.log and the fixed code.
- Implement keyboard navigation support including a skip-to-content link and logical tab order.
- Add a brief manual test checklist as HTML comments at the end of the file.