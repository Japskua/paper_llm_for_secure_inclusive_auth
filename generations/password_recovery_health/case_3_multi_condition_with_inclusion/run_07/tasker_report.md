# TASKER REPORT — Iteration 3 · Step 7

## SUMMARY
- Raw tasks from Tasker: 4
- Effective task_list after retention: 4
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Gate each protected client route using a freshly retrieved `/api/state`: permit `/mfa` only for `mfaPending`, recovery routes only for their matching recovery stage, `/privacy` only for an authenticated verified session, and `/confirmation` only when `privacyAccepted` is true. Redirect invalid direct navigation to the valid next step and show a clear status message.","After every successful state-changing API call (`/api/recovery-request`, `/api/recovery-verify`, `/api/password`, `/api/mfa-verify`, `/api/privacy-accept`, `/api/pause`, and `/api/resume`), refresh or replace the client state from `/api/state` before rendering the next view.","Render “Pause and return later” on the privacy screen whenever the server state reports an active recovery flow, including recovery stage `privacy`.","Redesign throttling keys so `Origin` and `X-Forwarded-For` cannot create independent rate-limit buckets. Use a trusted server-derived client address when available, or session/account-based throttling with a bounded global fallback."]}
```

## PARSED_TASKS
- Gate each protected client route using a freshly retrieved /api/state: permit /mfa only for mfaPending, recovery routes only for their matching recovery stage, /privacy only for an authenticated verified session, and /confirmation only when privacyAccepted is true. Redirect invalid direct navigation to the valid next step and show a clear status message.
- After every successful state-changing API call (/api/recovery-request, /api/recovery-verify, /api/password, /api/mfa-verify, /api/privacy-accept, /api/pause, and /api/resume), refresh or replace the client state from /api/state before rendering the next view.
- Render “Pause and return later” on the privacy screen whenever the server state reports an active recovery flow, including recovery stage privacy.
- Redesign throttling keys so Origin and X-Forwarded-For cannot create independent rate-limit buckets. Use a trusted server-derived client address when available, or session/account-based throttling with a bounded global fallback.