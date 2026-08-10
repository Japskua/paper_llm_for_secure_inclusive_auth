# TASKER REPORT — Iteration 2 · Step 4

## SUMMARY
- Raw tasks from Tasker: 4
- Effective task_list after retention: 4
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Add a client-side refreshSession() function that calls /api/session, updates csrf and session, and invoke it after every successful sensitive API request before calling go(...) (verify, reset-password, mfa/verify, privacy/accept, and appointment/confirm).","In the recovery form submit handler, set status.hidden = false before displaying the API result so recovery feedback is visible.","Change recovery issuance so a syntactically valid identifier does not automatically authorize reset of protected-account. Use server-side account eligibility/ownership logic; retain the same generic response for unknown identifiers, and limit testing-token delivery to an explicitly controlled mock recovery scenario rather than arbitrary submitted identifiers.","Add expiresAt to SessionState, set it when creating sessions, reject and delete expired sessions in sessionFor(), and align server-side expiration with the cookie Max-Age."]}
```

## PARSED_TASKS
- Add a client-side refreshSession() function that calls /api/session, updates csrf and session, and invoke it after every successful sensitive API request before calling go(...) (verify, reset-password, mfa/verify, privacy/accept, and appointment/confirm).
- In the recovery form submit handler, set status.hidden = false before displaying the API result so recovery feedback is visible.
- Change recovery issuance so a syntactically valid identifier does not automatically authorize reset of protected-account. Use server-side account eligibility/ownership logic; retain the same generic response for unknown identifiers, and limit testing-token delivery to an explicitly controlled mock recovery scenario rather than arbitrary submitted identifiers.
- Add expiresAt to SessionState, set it when creating sessions, reject and delete expired sessions in sessionFor(), and align server-side expiration with the cookie Max-Age.