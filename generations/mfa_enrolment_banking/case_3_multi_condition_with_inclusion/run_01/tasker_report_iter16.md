# TASKER REPORT — Iteration 16 · Step 46

## SUMMARY
- Raw tasks from Tasker: 4
- Effective task_list after retention: 4
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Add a CSRF-protected authenticated recovery-code verification endpoint that accepts only `AAAAA-BBBBB`, derives the account solely from the server-side session, compares HMACs in constant time, and consumes the matching code immediately on success.","Apply recovery-code failure controls in the verification endpoint: count malformed, invalid, and already-used submissions; lock recovery verification after `MAX_FAILURES`; reset failures after success; and return clear retry or lockout messages.","Add a mobile recovery-code verification entry point and screen with a labeled `autocomplete=\"one-time-code\"` input, an `AAAAA-BBBBB` example, one primary submit action, and plain success, retry, and lockout confirmations.","Associate every visible form label with a stable input `id` using matching `for` attributes, including email, password, OTP, and recovery-code fields."]}
```

## PARSED_TASKS
- Add a CSRF-protected authenticated recovery-code verification endpoint that accepts only AAAAA-BBBBB, derives the account solely from the server-side session, compares HMACs in constant time, and consumes the matching code immediately on success.
- Apply recovery-code failure controls in the verification endpoint: count malformed, invalid, and already-used submissions; lock recovery verification after `MAX_FAILURES`; reset failures after success; and return clear retry or lockout messages.
- Add a mobile recovery-code verification entry point and screen with a labeled autocomplete="one-time-code" input, an AAAAA-BBBBB example, one primary submit action, and plain success, retry, and lockout confirmations.
- Associate every visible form label with a stable input id using matching for attributes, including email, password, OTP, and recovery-code fields.