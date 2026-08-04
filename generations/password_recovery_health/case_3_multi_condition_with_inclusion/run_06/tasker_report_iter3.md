# TASKER REPORT — Iteration 3 · Step 7

## SUMMARY
- Raw tasks from Tasker: 5
- Effective task_list after retention: 5
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Move the browser JavaScript from the inline <script> block into a same-origin JavaScript response route, such as GET /app.js, while keeping the route implementation and JavaScript source inside app.ts.","Update the page HTML to load the client code with <script src=\"/app.js\" defer></script> and update CSP to remove nonce-based inline-script authorization and enforce script-src 'self'.","Extend /api/session to return a server-derived recovery state, such as request, code, mfa, password, or finished, based on the current session’s reset, verification, MFA, and completion state.","On browser startup, reconcile localStorage progress with the server-provided recovery state; reset the UI to the earliest valid step when local progress is stale or unauthorized.","Add clear user-facing recovery-state messages for expired, replaced, or unavailable reset progress, including an explicit action to return to step 1 or request a fresh code."]}
```

## PARSED_TASKS
- Move the browser JavaScript from the inline <script> block into a same-origin JavaScript response route, such as GET /app.js, while keeping the route implementation and JavaScript source inside app.ts.
- Update the page HTML to load the client code with <script src="/app.js" defer></script> and update CSP to remove nonce-based inline-script authorization and enforce script-src 'self'.
- Extend /api/session to return a server-derived recovery state, such as request, code, mfa, password, or finished, based on the current session’s reset, verification, MFA, and completion state.
- On browser startup, reconcile localStorage progress with the server-provided recovery state; reset the UI to the earliest valid step when local progress is stale or unauthorized.
- Add clear user-facing recovery-state messages for expired, replaced, or unavailable reset progress, including an explicit action to return to step 1 or request a fresh code.