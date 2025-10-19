# TASKER REPORT — Iteration 2 · Step 4

## SUMMARY
- Raw tasks from Tasker: 8
- Effective task_list after retention: 8
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Add CSRF-protected POST /api/last-view that accepts JSON {view} ∈ {login, requestReset, verify, setPassword, mfa, success, help}, validates/sanitizes it, saves to session.lastView, and responds 200 {ok:true}.",
    "In GET \"/\" rendering, set meta data-last to setPassword if session.canSetPassword, else mfa if session.mfaPending, else session.lastView or \"login\".",
    "On first client load, read meta data-last and set window.location.hash to that view exactly once to restore progress.",
    "Modify show(view) to POST {view} with the CSRF token to /api/last-view after routing; log failures but do not block UI.",
    "Remove all inline style=\"\" attributes from the HTML markup.",
    "Create equivalent CSS utility classes in the existing nonced <style> block and replace prior inline styles with these class names.",
    "Confirm CSP header keeps style-src 'self' 'nonce-<nonce>' (no 'unsafe-inline') and that the page renders without CSP violations.",
    "Optionally embed meta flags data-can-set-password and data-mfa-pending and, on initial route, prefer setPassword/mfa when true."
  ]
}
```

## PARSED_TASKS
- Add CSRF-protected POST /api/last-view that accepts JSON {view} ∈ {login, requestReset, verify, setPassword, mfa, success, help}, validates/sanitizes it, saves to session.lastView, and responds 200 {ok:true}.
- In GET "/" rendering, set meta data-last to setPassword if session.canSetPassword, else mfa if session.mfaPending, else session.lastView or "login".
- On first client load, read meta data-last and set window.location.hash to that view exactly once to restore progress.
- Modify show(view) to POST {view} with the CSRF token to /api/last-view after routing; log failures but do not block UI.
- Remove all inline style="" attributes from the HTML markup.
- Create equivalent CSS utility classes in the existing nonced <style> block and replace prior inline styles with these class names.
- Confirm CSP header keeps style-src 'self' 'nonce-<nonce>' (no 'unsafe-inline') and that the page renders without CSP violations.
- Optionally embed meta flags data-can-set-password and data-mfa-pending and, on initial route, prefer setPassword/mfa when true.