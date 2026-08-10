# TASKER REPORT — Iteration 2 · Step 4

## SUMMARY
- Raw tasks from Tasker: 5
- Effective task_list after retention: 5
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Replace host-derived HTTP redirect construction with a fixed configured HTTPS origin or strict localhost allowlist, rejecting unexpected Host headers rather than redirecting to them.","Add a per-session reset-verification failure counter that increments for every invalid `/api/verify-reset` submission and invalidates or locks the recovery flow after a small threshold with a generic `429` response.","Consume a reset token immediately upon successful verification and issue a separate server-side, account-bound, short-lived, single-use verified-reset grant required by the password-update endpoint.","Add a non-exposed mock account model with a server-side email hash associated with its password hash; issue a usable reset token only when the submitted email matches that account while returning the same generic response for all emails.","Ensure non-matching email submissions return no `testToken`, create no verified-reset grant, and cannot change the mock account password; retain browser-console mock delivery only for the configured account."]}
```

## PARSED_TASKS
- Replace host-derived HTTP redirect construction with a fixed configured HTTPS origin or strict localhost allowlist, rejecting unexpected Host headers rather than redirecting to them.
- Add a per-session reset-verification failure counter that increments for every invalid /api/verify-reset submission and invalidates or locks the recovery flow after a small threshold with a generic 429 response.
- Consume a reset token immediately upon successful verification and issue a separate server-side, account-bound, short-lived, single-use verified-reset grant required by the password-update endpoint.
- Add a non-exposed mock account model with a server-side email hash associated with its password hash; issue a usable reset token only when the submitted email matches that account while returning the same generic response for all emails.
- Ensure non-matching email submissions return no testToken, create no verified-reset grant, and cannot change the mock account password; retain browser-console mock delivery only for the configured account.