# TASKER REPORT — Iteration 2 · Step 4

## SUMMARY
- Raw tasks from Tasker: 6
- Effective task_list after retention: 6
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Use one freshly generated CSP nonce for each root-page response: pass that same nonce to both the inline script and the CSP header, and remove the unreachable duplicate root-route condition.","Enforce server-side session expiration using `createdAt` and `SESSION_AGE_SECONDS`; delete expired session records and reject all requests using expired session IDs.","Rate-limit recovery, token verification, MFA, and login attempts with keys that cannot be reset by creating a new session; scope limits to the relevant action and protected account or recovery context.","Stop trusting arbitrary `X-Forwarded-For` headers for rate limiting; use a Bun-provided peer address when available, or a conservative local-deployment key when no trusted proxy is configured.","Remove server-side `console.log` calls that simulate recovery delivery or verification; keep all required mock-delivery and verification logs in the browser console.","Verify in a CSP-enforcing browser that bootstrap, recovery request, manual token entry, password update, MFA, login, and privacy acceptance execute successfully without blocked-script errors."]}
```

## PARSED_TASKS
- Use one freshly generated CSP nonce for each root-page response: pass that same nonce to both the inline script and the CSP header, and remove the unreachable duplicate root-route condition.
- Enforce server-side session expiration using createdAt and `SESSION_AGE_SECONDS`; delete expired session records and reject all requests using expired session IDs.
- Rate-limit recovery, token verification, MFA, and login attempts with keys that cannot be reset by creating a new session; scope limits to the relevant action and protected account or recovery context.
- Stop trusting arbitrary X-Forwarded-For headers for rate limiting; use a Bun-provided peer address when available, or a conservative local-deployment key when no trusted proxy is configured.
- Remove server-side console.log calls that simulate recovery delivery or verification; keep all required mock-delivery and verification logs in the browser console.
- Verify in a CSP-enforcing browser that bootstrap, recovery request, manual token entry, password update, MFA, login, and privacy acceptance execute successfully without blocked-script errors.