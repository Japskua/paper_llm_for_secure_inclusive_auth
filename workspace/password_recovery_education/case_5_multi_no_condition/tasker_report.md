# TASKER REPORT — Iteration 1 · Step 1

## SUMMARY
- Raw tasks from Tasker: 15
- Effective task_list after retention: 15
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Create index.html with semantic HTML structure, inline <style> and <script>, and a top comment mapping sections to the spec.",
    "Implement a Login view with email/username and password fields plus a 'Forgot password?' control that switches views without reload.",
    "Add a Recovery Request view with email input; on submit, console.log a deterministic reset code and display a 'code sent' notice.",
    "Implement a Code + New Password view that verifies the entered code against the deterministic value and shows errors on mismatch.",
    "Add a real-time password policy checklist and strength indicator (length, upper, lower, number, symbol) that gates submission.",
    "Add show/hide toggles for both password and confirm fields that switch input masking.",
    "Implement confirm-password match validation with inline error messaging that blocks submission until matched.",
    "On successful reset, console.log success and transition to an authenticated dashboard view.",
    "Create a dashboard with a course list selector and a file upload control; on 'upload', console.log the selected course and file name.",
    "Add a 'Log out' action that returns to Login and resets in-memory state to allow retrying the flow.",
    "Add accessible labels, described-by text, aria-live regions for status/errors, and move focus to the first field on each view change.",
    "Style inline CSS for readable layout and clear states (error in red, success in green) with responsive basics.",
    "Document and implement the deterministic token generator in comments (e.g., derived from email) to ensure repeatable codes.",
    "Emit console.log entries for each stage: email sent, code verified, password reset, login success, course selected, file uploaded.",
    "Verify the app runs offline with no external dependencies; ensure all logic executes entirely in the browser."
  ]
}
```

## PARSED_TASKS
- Create index.html with semantic HTML structure, inline <style> and <script>, and a top comment mapping sections to the spec.
- Implement a Login view with email/username and password fields plus a 'Forgot password?' control that switches views without reload.
- Add a Recovery Request view with email input; on submit, console.log a deterministic reset code and display a 'code sent' notice.
- Implement a Code + New Password view that verifies the entered code against the deterministic value and shows errors on mismatch.
- Add a real-time password policy checklist and strength indicator (length, upper, lower, number, symbol) that gates submission.
- Add show/hide toggles for both password and confirm fields that switch input masking.
- Implement confirm-password match validation with inline error messaging that blocks submission until matched.
- On successful reset, console.log success and transition to an authenticated dashboard view.
- Create a dashboard with a course list selector and a file upload control; on 'upload', console.log the selected course and file name.
- Add a 'Log out' action that returns to Login and resets in-memory state to allow retrying the flow.
- Add accessible labels, described-by text, aria-live regions for status/errors, and move focus to the first field on each view change.
- Style inline CSS for readable layout and clear states (error in red, success in green) with responsive basics.
- Document and implement the deterministic token generator in comments (e.g., derived from email) to ensure repeatable codes.
- Emit console.log entries for each stage: email sent, code verified, password reset, login success, course selected, file uploaded.
- Verify the app runs offline with no external dependencies; ensure all logic executes entirely in the browser.