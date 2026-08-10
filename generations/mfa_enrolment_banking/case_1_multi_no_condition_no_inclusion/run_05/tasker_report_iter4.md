# TASKER REPORT — Iteration 4 · Step 10

## SUMMARY
- Raw tasks from Tasker: 2
- Effective task_list after retention: 2
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Add a server-side failed-sign-in attempt limiter and lockout mechanism that cannot be bypassed by creating a new anonymous session. Key it using an appropriate server-controlled identifier, such as a normalized submitted login identifier combined with a client/IP rate-limit bucket, and return the same generic sign-in error for locked and invalid attempts.","Replace short-circuit plaintext credential comparisons in `/api/signin` with a uniform credential-validation path that performs equivalent fixed-cost work for both unknown-login and wrong-password submissions, using fixed-length hashes and constant-time comparison. Reset the sign-in failure state only after successful authentication."]}
```

## PARSED_TASKS
- Add a server-side failed-sign-in attempt limiter and lockout mechanism that cannot be bypassed by creating a new anonymous session. Key it using an appropriate server-controlled identifier, such as a normalized submitted login identifier combined with a client/IP rate-limit bucket, and return the same generic sign-in error for locked and invalid attempts.
- Replace short-circuit plaintext credential comparisons in /api/signin with a uniform credential-validation path that performs equivalent fixed-cost work for both unknown-login and wrong-password submissions, using fixed-length hashes and constant-time comparison. Reset the sign-in failure state only after successful authentication.