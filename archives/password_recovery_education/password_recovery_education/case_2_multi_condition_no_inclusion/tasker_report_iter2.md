# TASKER REPORT — Iteration 2 · Step 4

## SUMMARY
- Raw tasks from Tasker: 14
- Effective task_list after retention: 14
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Modify /api/validate-reset to mark the matched token as used immediately and store resetUser and resetToken in the current session upon successful validation; subsequent validations of the same token must return 400/401.",
    "Ensure /api/set-password authorizes only via session.resetUser and session.resetToken (ignore any token in the request body) and succeeds once; after success, clear session.resetUser and session.resetToken.",
    "Extend the Session data to include mfaExpiresAt (number), mfaAttempts (number), and mfaNonce (string).",
    "In /api/login, when issuing MFA, set mfaExpiresAt = now + 5 minutes, mfaAttempts = 5, generate a random mfaNonce, and return the mfaNonce to the client.",
    "Update the client to include the provided mfaNonce in the body of /api/verify-mfa requests.",
    "In /api/verify-mfa, before comparing the code, if now > mfaExpiresAt then clear MFA state and return 401 with a generic 'MFA expired; sign in again' message.",
    "In /api/verify-mfa, decrement mfaAttempts on each failed code; when attempts reach 0, clear MFA state and return 429 with a generic 'Too many MFA attempts; sign in again' message.",
    "Require the provided mfaNonce to match the session mfaNonce in /api/verify-mfa; on mismatch return 401 and do not reveal details.",
    "Clear MFA state (pendingMFA, mfaCode, mfaExpiresAt, mfaAttempts, mfaNonce) after successful verification or terminal failure/expiry.",
    "Add user-safe messages to the client Logs panel for MFA expiry and lockout responses without leaking secrets.",
    "Create a global rate limiter store (e.g., Map keyed by `${ip}:${action}`) and a helper checkRateGlobal(ip, action, limit = 5, windowMs = 300000) that prunes old timestamps and returns allow/deny.",
    "Replace per-session rate checks in /api/login with checkRateGlobal(scoped by IP, action 'login') so that multiple sessions from the same IP count toward the same limit.",
    "Replace per-session rate checks in /api/request-reset with checkRateGlobal(scoped by IP, action 'request-reset').",
    "Apply checkRateGlobal to /api/verify-mfa (action 'verify-mfa') with a limit like 5 attempts per 5 minutes per IP; the 6th attempt within the window returns 429."
  ]
}
```

## PARSED_TASKS
- Modify /api/validate-reset to mark the matched token as used immediately and store resetUser and resetToken in the current session upon successful validation; subsequent validations of the same token must return 400/401.
- Ensure /api/set-password authorizes only via session.resetUser and session.resetToken (ignore any token in the request body) and succeeds once; after success, clear session.resetUser and session.resetToken.
- Extend the Session data to include mfaExpiresAt (number), mfaAttempts (number), and mfaNonce (string).
- In /api/login, when issuing MFA, set mfaExpiresAt = now + 5 minutes, mfaAttempts = 5, generate a random mfaNonce, and return the mfaNonce to the client.
- Update the client to include the provided mfaNonce in the body of /api/verify-mfa requests.
- In /api/verify-mfa, before comparing the code, if now > mfaExpiresAt then clear MFA state and return 401 with a generic 'MFA expired; sign in again' message.
- In /api/verify-mfa, decrement mfaAttempts on each failed code; when attempts reach 0, clear MFA state and return 429 with a generic 'Too many MFA attempts; sign in again' message.
- Require the provided mfaNonce to match the session mfaNonce in /api/verify-mfa; on mismatch return 401 and do not reveal details.
- Clear MFA state (pendingMFA, mfaCode, mfaExpiresAt, mfaAttempts, mfaNonce) after successful verification or terminal failure/expiry.
- Add user-safe messages to the client Logs panel for MFA expiry and lockout responses without leaking secrets.
- Create a global rate limiter store (e.g., Map keyed by `${ip}:${action}`) and a helper checkRateGlobal(ip, action, limit = 5, windowMs = 300000) that prunes old timestamps and returns allow/deny.
- Replace per-session rate checks in /api/login with checkRateGlobal(scoped by IP, action 'login') so that multiple sessions from the same IP count toward the same limit.
- Replace per-session rate checks in /api/request-reset with checkRateGlobal(scoped by IP, action 'request-reset').
- Apply checkRateGlobal to /api/verify-mfa (action 'verify-mfa') with a limit like 5 attempts per 5 minutes per IP; the 6th attempt within the window returns 429.