# TASKER REPORT — Iteration 2 · Step 4

## SUMMARY
- Raw tasks from Tasker: 3
- Effective task_list after retention: 3
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Remove the HTTP fallback and require certs/cert.pem and certs/key.pem before starting the Bun server; always configure TLS and always set Secure cookies and HSTS.","Add a server-side session lifetime, validate it in getSession and before sensitive actions, delete expired sessions, and periodically clean stale entries from the sessions map.","Generate a fresh CSP nonce for every HTML response, pass that nonce to both page(...) and baseHeaders(...), and use the response-specific nonce for the inline stylesheet and script."]}
```

## PARSED_TASKS
- Remove the HTTP fallback and require certs/cert.pem and certs/key.pem before starting the Bun server; always configure TLS and always set Secure cookies and HSTS.
- Add a server-side session lifetime, validate it in getSession and before sensitive actions, delete expired sessions, and periodically clean stale entries from the sessions map.
- Generate a fresh CSP nonce for every HTML response, pass that nonce to both page(...) and baseHeaders(...), and use the response-specific nonce for the inline stylesheet and script.