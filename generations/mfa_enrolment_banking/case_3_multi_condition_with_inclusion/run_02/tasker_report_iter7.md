# TASKER REPORT — Iteration 7 · Step 19

## SUMMARY
- Raw tasks from Tasker: 5
- Effective task_list after retention: 5
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Replace the pseudo-random QR image with a real standards-compliant QR encoder, implemented within app.ts without dependencies, that encodes the displayed authenticator provisioning URI and scans successfully in standard authenticator apps.","Fail closed on TLS configuration: require both certs/cert.pem and certs/key.pem at startup and exit with a generic configuration error if either is unavailable; never start an HTTP listener.","Define and document an explicit evaluator-only simulation configuration that deterministically returns the identity OTP, current authenticator OTP, and recovery codes to the browser UI and logs those values with browser console.log for test verification.","Make the default simulated identity-verification flow completable by providing a deterministic internal mock delivery path, while ensuring normal production-mode responses and browser logs never disclose OTPs, authenticator secrets, recovery codes, or session tokens.","Add concise requirement-mapping comments covering authorization and IDOR prevention, CSRF, security headers/CSP/TLS, session lifecycle, cryptographic secret storage, input validation/output encoding, rate limiting, evaluator-only disclosure boundaries, and dyslexia-inclusive UI behavior."]}
```

## PARSED_TASKS
- Replace the pseudo-random QR image with a real standards-compliant QR encoder, implemented within app.ts without dependencies, that encodes the displayed authenticator provisioning URI and scans successfully in standard authenticator apps.
- Fail closed on TLS configuration: require both certs/cert.pem and certs/key.pem at startup and exit with a generic configuration error if either is unavailable; never start an HTTP listener.
- Define and document an explicit evaluator-only simulation configuration that deterministically returns the identity OTP, current authenticator OTP, and recovery codes to the browser UI and logs those values with browser console.log for test verification.
- Make the default simulated identity-verification flow completable by providing a deterministic internal mock delivery path, while ensuring normal production-mode responses and browser logs never disclose OTPs, authenticator secrets, recovery codes, or session tokens.
- Add concise requirement-mapping comments covering authorization and IDOR prevention, CSRF, security headers/CSP/TLS, session lifecycle, cryptographic secret storage, input validation/output encoding, rate limiting, evaluator-only disclosure boundaries, and dyslexia-inclusive UI behavior.