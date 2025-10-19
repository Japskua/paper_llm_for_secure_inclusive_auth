# TASKER REPORT — Iteration 2 · Step 4

## SUMMARY
- Raw tasks from Tasker: 9
- Effective task_list after retention: 9
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Serve the SPA JavaScript from GET /app.js with Content-Type application/javascript, and reference it in HTML via <script src=\"/app.js\" defer></script>.",
    "Remove the inline <script> from the HTML template and ensure no inline event handler attributes exist in HTML.",
    "Update CSP to set script-src 'self' (no nonce), and remove all script nonce generation/usage while keeping other strict directives unchanged.",
    "Ensure the external JS reads the CSRF token (e.g., from a meta tag or cookie) and sends it as X-CSRF-Token on all sensitive POST requests.",
    "Make GET /api/reset/preview read-only: do not write to session; only validate the token and return { ok: boolean, reason?: string }.",
    "Require POST /api/reset/verify to include { token } in the JSON body and a valid CSRF token; on success set session verification and invalidate the reset token.",
    "Update the verify view to always POST the token (from URL or manual input) to /api/reset/verify with CSRF, removing any reliance on preview-side effects.",
    "Add or update code comments mapping these changes to Requirements 1 (CSRF coverage on sensitive routes) and 2 (no inline scripts, XSS mitigations).",
    "Manually verify that visiting a reset link calls GET /api/reset/preview without changing session, and that only the CSRF-protected POST /api/reset/verify completes verification."
  ]
}
```

## PARSED_TASKS
- Serve the SPA JavaScript from GET /app.js with Content-Type application/javascript, and reference it in HTML via <script src="/app.js" defer></script>.
- Remove the inline <script> from the HTML template and ensure no inline event handler attributes exist in HTML.
- Update CSP to set script-src 'self' (no nonce), and remove all script nonce generation/usage while keeping other strict directives unchanged.
- Ensure the external JS reads the CSRF token (e.g., from a meta tag or cookie) and sends it as X-CSRF-Token on all sensitive POST requests.
- Make GET /api/reset/preview read-only: do not write to session; only validate the token and return { ok: boolean, reason?: string }.
- Require POST /api/reset/verify to include { token } in the JSON body and a valid CSRF token; on success set session verification and invalidate the reset token.
- Update the verify view to always POST the token (from URL or manual input) to /api/reset/verify with CSRF, removing any reliance on preview-side effects.
- Add or update code comments mapping these changes to Requirements 1 (CSRF coverage on sensitive routes) and 2 (no inline scripts, XSS mitigations).
- Manually verify that visiting a reset link calls GET /api/reset/preview without changing session, and that only the CSRF-protected POST /api/reset/verify completes verification.