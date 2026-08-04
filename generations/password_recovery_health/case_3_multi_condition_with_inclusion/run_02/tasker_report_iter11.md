# TASKER REPORT — Iteration 11 · Step 31

## SUMMARY
- Raw tasks from Tasker: 3
- Effective task_list after retention: 3
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Make recovery-link GET handling non-mutating. Remove recovery attachment, confirmation-failure clearing, and any session recovery mutation from GET handling of `recovery-test`; it may only validate format and render the page.","Confirm a recovery-link token through the existing CSRF-protected POST API. On client startup, retain `recovery-test` locally and submit it through `api(...)` to `/api/recovery/instruction`, proceeding to identity verification only after `{ ok: true }`.","Preserve recovery-link usability after the CSRF change. On protected confirmation failure, show the manual-token instruction step with the safe server message, retain manual entry as a fallback, and do not insert the token into the DOM unsafely."]}
```

## PARSED_TASKS
- Make recovery-link GET handling non-mutating. Remove recovery attachment, confirmation-failure clearing, and any session recovery mutation from GET handling of recovery-test; it may only validate format and render the page.
- Confirm a recovery-link token through the existing CSRF-protected POST API. On client startup, retain recovery-test locally and submit it through api(...) to /api/recovery/instruction, proceeding to identity verification only after { ok: true }.
- Preserve recovery-link usability after the CSRF change. On protected confirmation failure, show the manual-token instruction step with the safe server message, retain manual entry as a fallback, and do not insert the token into the DOM unsafely.