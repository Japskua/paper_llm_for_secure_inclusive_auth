# TASKER REPORT — Iteration 2 · Step 4

## SUMMARY
- Raw tasks from Tasker: 6
- Effective task_list after retention: 6
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Enforce token expiry in /api/verify-reset: if now > token.expiresAt, return 400 with message \"Token expired\" and do not mark the token used or set session flags.",
    "Serve the SPA JavaScript from a GET /app.js route generated in app.ts with Content-Type application/javascript.",
    "Remove the inline <script> from the HTML and include <script src=\"/app.js\" defer></script> instead.",
    "Update the CSP header to allow script-src 'self' and remove the script nonce requirement (keep other directives unchanged).",
    "Ensure the client fetch helper reads the CSRF token from <meta name=\"csrf-token\"> and sends X-CSRF-Token on all /api/* requests when loaded from /app.js.",
    "Update the verify view to display server error messages (e.g., \"Token expired\") returned by /api/verify-reset."
  ]
}
```

## PARSED_TASKS
- Enforce token expiry in /api/verify-reset: if now > token.expiresAt, return 400 with message "Token expired" and do not mark the token used or set session flags.
- Serve the SPA JavaScript from a GET /app.js route generated in app.ts with Content-Type application/javascript.
- Remove the inline <script> from the HTML and include <script src="/app.js" defer></script> instead.
- Update the CSP header to allow script-src 'self' and remove the script nonce requirement (keep other directives unchanged).
- Ensure the client fetch helper reads the CSRF token from <meta name="csrf-token"> and sends X-CSRF-Token on all /api/* requests when loaded from /app.js.
- Update the verify view to display server error messages (e.g., "Token expired") returned by /api/verify-reset.