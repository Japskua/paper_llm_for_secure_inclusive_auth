# TASKER REPORT — Iteration 7 · Step 19

## SUMMARY
- Raw tasks from Tasker: 21
- Effective task_list after retention: 21
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Create an account-scoped MFA store keyed by authenticated user ID, containing encrypted TOTP metadata, hashed recovery codes, accepted TOTP steps, and verification-attempt state.","Persist the account-scoped MFA store across server restarts without storing plaintext TOTP secrets or recovery codes.","Load or derive MFA encryption key material from protected server-side configuration rather than generating process-only key material.","Validate `/api/auth/signin` request parsing, content type, size, and email format; reject invalid input with a generic actionable response.","Bind the owner-confirmation and identity-verification flow to the validated email held in the server-side sign-in session.","Implement a CSRF-protected identity-code re-request endpoint that invalidates the old code and creates a new single-use, time-bound code.","Add a “Send a new code” identity-verification action that logs the simulated replacement code only in the browser console and confirms the next step plainly.","Generate a cryptographically secure Base32 TOTP secret after identity verification and encrypt it before storing it in the authenticated account’s MFA record.","Create an `otpauth://` URI for the enrolled account and render an inline QR representation without external assets.","Show a manual TOTP secret fallback with an accessible copy-to-clipboard control, and log provisioning details only in the browser console.","Implement an authenticated, CSRF-protected TOTP verification endpoint that validates a six-digit authenticator code against the encrypted secret and allowed time windows.","Record accepted TOTP time steps per account so a valid TOTP code cannot be replayed.","Mark MFA as enrolled only after successful TOTP verification, and prevent recovery-code generation before that state is reached.","Track verification failure counts and lockouts per account and verification purpose, resetting the count when an expired lockout is cleared.","Generate account-scoped recovery codes only after TOTP enrolment, store only secure hashes, and consume each code after one successful use.","Add recovery-code controls to reveal or hide codes, copy all codes, and download or print a safe-save copy.","Add a CSRF-protected recovery-code regeneration flow with a clear warning, explicit confirmation, replacement of old hashes, and browser-console logging of the newly simulated codes.","Replace implicit named-element globals in client code with explicit `querySelector` or equivalent DOM references.","Use a complete semantic HTML document with explicit `<html>`, `<head>`, and `<body>` elements.","Provide a concise, consistently placed help or hint control on every enrolment step, including input examples and clear retry guidance.","Add concise code comments in server and client sections mapping authentication, encryption, authorization, CSRF, and dyslexia-focused UI behavior to the stated requirements."]}
```

## PARSED_TASKS
- Create an account-scoped MFA store keyed by authenticated user ID, containing encrypted TOTP metadata, hashed recovery codes, accepted TOTP steps, and verification-attempt state.
- Persist the account-scoped MFA store across server restarts without storing plaintext TOTP secrets or recovery codes.
- Load or derive MFA encryption key material from protected server-side configuration rather than generating process-only key material.
- Validate /api/auth/signin request parsing, content type, size, and email format; reject invalid input with a generic actionable response.
- Bind the owner-confirmation and identity-verification flow to the validated email held in the server-side sign-in session.
- Implement a CSRF-protected identity-code re-request endpoint that invalidates the old code and creates a new single-use, time-bound code.
- Add a “Send a new code” identity-verification action that logs the simulated replacement code only in the browser console and confirms the next step plainly.
- Generate a cryptographically secure Base32 TOTP secret after identity verification and encrypt it before storing it in the authenticated account’s MFA record.
- Create an otpauth:// URI for the enrolled account and render an inline QR representation without external assets.
- Show a manual TOTP secret fallback with an accessible copy-to-clipboard control, and log provisioning details only in the browser console.
- Implement an authenticated, CSRF-protected TOTP verification endpoint that validates a six-digit authenticator code against the encrypted secret and allowed time windows.
- Record accepted TOTP time steps per account so a valid TOTP code cannot be replayed.
- Mark MFA as enrolled only after successful TOTP verification, and prevent recovery-code generation before that state is reached.
- Track verification failure counts and lockouts per account and verification purpose, resetting the count when an expired lockout is cleared.
- Generate account-scoped recovery codes only after TOTP enrolment, store only secure hashes, and consume each code after one successful use.
- Add recovery-code controls to reveal or hide codes, copy all codes, and download or print a safe-save copy.
- Add a CSRF-protected recovery-code regeneration flow with a clear warning, explicit confirmation, replacement of old hashes, and browser-console logging of the newly simulated codes.
- Replace implicit named-element globals in client code with explicit querySelector or equivalent DOM references.
- Use a complete semantic HTML document with explicit <html>, <head>, and <body> elements.
- Provide a concise, consistently placed help or hint control on every enrolment step, including input examples and clear retry guidance.
- Add concise code comments in server and client sections mapping authentication, encryption, authorization, CSRF, and dyslexia-focused UI behavior to the stated requirements.