# TASKER REPORT — Iteration 6 · Step 16

## SUMMARY
- Raw tasks from Tasker: 3
- Effective task_list after retention: 3
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Create a server-side failed-login rate-limit record keyed by normalized email identifier (and optionally source IP), independent of anonymous session state.","Make `/api/login` check and increment the identifier-scoped failure record for invalid credentials, and return HTTP 429 while its lockout period is active regardless of a newly created session.","Clear the successful account identifier's failure record after successful login while retaining session-ID rotation and existing generic authentication responses."]}
```

## PARSED_TASKS
- Create a server-side failed-login rate-limit record keyed by normalized email identifier (and optionally source IP), independent of anonymous session state.
- Make /api/login check and increment the identifier-scoped failure record for invalid credentials, and return HTTP 429 while its lockout period is active regardless of a newly created session.
- Clear the successful account identifier's failure record after successful login while retaining session-ID rotation and existing generic authentication responses.