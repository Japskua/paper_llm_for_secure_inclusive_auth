# TASKER REPORT — Iteration 4 · Step 10

## SUMMARY
- Raw tasks from Tasker: 7
- Effective task_list after retention: 7
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "In handleSetNewPassword, if a real and unexpired handle is provided and the newPassword fails the policy, return HTTP 400 with JSON { ok: false, message: <policy reason> } and invalidate the handle.",
    "Ensure handleSetNewPassword keeps returning generic 200 { ok: true } for invalid/expired/decoy handles to preserve enumeration resistance.",
    "Add or update a password validation helper to return a clear human-readable policy error string used in the 400 response.",
    "Update renderSetNewPassword to check the /api/set-new-password response; on non-OK, display info(message, 'error') and do not redirect.",
    "Fix error styling calls by passing 'error' to info() (not appendChild) in catch blocks of renderLogin, renderMFA, renderForgot, renderVerify, renderSetNewPassword, and renderPrivacy.",
    "Search the client code and correct any remaining instances of app.appendChild(info(...), 'error') to app.appendChild(info(..., 'error')).",
    "Optional: On invalid login credentials, show a visible error via info('Invalid credentials', 'error') in renderLogin instead of relying only on console logs."
  ]
}
```

## PARSED_TASKS
- In handleSetNewPassword, if a real and unexpired handle is provided and the newPassword fails the policy, return HTTP 400 with JSON { ok: false, message: <policy reason> } and invalidate the handle.
- Ensure handleSetNewPassword keeps returning generic 200 { ok: true } for invalid/expired/decoy handles to preserve enumeration resistance.
- Add or update a password validation helper to return a clear human-readable policy error string used in the 400 response.
- Update renderSetNewPassword to check the /api/set-new-password response; on non-OK, display info(message, 'error') and do not redirect.
- Fix error styling calls by passing 'error' to info() (not appendChild) in catch blocks of renderLogin, renderMFA, renderForgot, renderVerify, renderSetNewPassword, and renderPrivacy.
- Search the client code and correct any remaining instances of app.appendChild(info(...), 'error') to app.appendChild(info(..., 'error')).
- Optional: On invalid login credentials, show a visible error via info('Invalid credentials', 'error') in renderLogin instead of relying only on console logs.