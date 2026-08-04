# TASKER REPORT — Iteration 2 · Step 4

## SUMMARY
- Raw tasks from Tasker: 5
- Effective task_list after retention: 5
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Require TLS certificates at startup: if certs/cert.pem or certs/key.pem is unavailable, log a clear server-console error and do not start the portal over plaintext HTTP.","If an HTTP listener is retained, make it redirect only to the fixed localhost HTTPS origin; serve all application routes exclusively from the TLS-enabled Bun server.","Add a server-side expiration timestamp to each recovery session, and have session lookup reject and delete expired session records regardless of cookie lifetime.","Use a short recovery-session lifetime and refresh its server-side expiration only after appropriate authenticated or sensitive progress; periodically remove expired sessions from in-memory storage.","Make the global error response include the same no-store and security headers as normal responses, including HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy."]}
```

## PARSED_TASKS
- Require TLS certificates at startup: if certs/cert.pem or certs/key.pem is unavailable, log a clear server-console error and do not start the portal over plaintext HTTP.
- If an HTTP listener is retained, make it redirect only to the fixed localhost HTTPS origin; serve all application routes exclusively from the TLS-enabled Bun server.
- Add a server-side expiration timestamp to each recovery session, and have session lookup reject and delete expired session records regardless of cookie lifetime.
- Use a short recovery-session lifetime and refresh its server-side expiration only after appropriate authenticated or sensitive progress; periodically remove expired sessions from in-memory storage.
- Make the global error response include the same no-store and security headers as normal responses, including HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.