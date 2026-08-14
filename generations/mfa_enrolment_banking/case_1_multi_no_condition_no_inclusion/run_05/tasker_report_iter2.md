# TASKER REPORT — Iteration 2 · Step 4

## SUMMARY
- Raw tasks from Tasker: 6
- Effective task_list after retention: 6
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Make session status loading use the supported secure API method and handle non-success responses explicitly so anonymous and authenticated states are accurate.","After successful sign-in, set client authentication state, reset identity/MFA state as needed, and navigate to the identity-verification route without redirecting back to sign-in.","Associate each successful demo sign-in with a stable opaque account ID derived from that authenticated identity instead of a shared hard-coded account.","Ensure every protected MFA handler uses only the account bound to the validated server-side session while preserving generic sign-in responses.","Add a recovery-code attempt state per account that records failed malformed, unknown, and already-used recovery-code submissions.","Reject recovery-code attempts during lockout, apply the configured lockout after the failure threshold, and reset recovery-code failures after a successful use."]}
```

## PARSED_TASKS
- Make session status loading use the supported secure API method and handle non-success responses explicitly so anonymous and authenticated states are accurate.
- After successful sign-in, set client authentication state, reset identity/MFA state as needed, and navigate to the identity-verification route without redirecting back to sign-in.
- Associate each successful demo sign-in with a stable opaque account ID derived from that authenticated identity instead of a shared hard-coded account.
- Ensure every protected MFA handler uses only the account bound to the validated server-side session while preserving generic sign-in responses.
- Add a recovery-code attempt state per account that records failed malformed, unknown, and already-used recovery-code submissions.
- Reject recovery-code attempts during lockout, apply the configured lockout after the failure threshold, and reset recovery-code failures after a successful use.