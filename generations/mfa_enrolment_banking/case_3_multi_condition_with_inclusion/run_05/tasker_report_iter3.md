# TASKER REPORT — Iteration 3 · Step 7

## SUMMARY
- Raw tasks from Tasker: 8
- Effective task_list after retention: 8
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Replace or correct the provisioning QR renderer so it generates a standards-compliant, scannable QR code for the authenticator URI, including all required metadata for its selected QR version.","Add per-session failed-attempt tracking, a maximum threshold, and timed lockout to authenticator OTP verification; return HTTP 429 with clear retry guidance while locked.","Generate a unique cryptographically random TOTP secret for every provisioning request, encrypt it at rest, and expose it only through the browser testing UI and browser console mock output.","Generate a unique cryptographically random, high-entropy recovery-code set for each successful MFA enrolment instead of reusing fixed codes.","Protect stored recovery codes with a stronger at-rest scheme using per-code random salt and a suitable slow KDF, or an equivalent keyed server-side hash design.","Use one consistent recovery-code alphabet in generation, UI examples, and server validation so every displayed code can be confirmed.","Generate a cryptographically random CSP nonce for every HTML response and apply that same response-specific nonce to the CSP header and inline style and script elements.","Change recovery-code confirmation so it either validates without consuming a code or clearly states before submission and after success that the submitted code is consumed and must be discarded."]}
```

## PARSED_TASKS
- Replace or correct the provisioning QR renderer so it generates a standards-compliant, scannable QR code for the authenticator URI, including all required metadata for its selected QR version.
- Add per-session failed-attempt tracking, a maximum threshold, and timed lockout to authenticator OTP verification; return HTTP 429 with clear retry guidance while locked.
- Generate a unique cryptographically random TOTP secret for every provisioning request, encrypt it at rest, and expose it only through the browser testing UI and browser console mock output.
- Generate a unique cryptographically random, high-entropy recovery-code set for each successful MFA enrolment instead of reusing fixed codes.
- Protect stored recovery codes with a stronger at-rest scheme using per-code random salt and a suitable slow KDF, or an equivalent keyed server-side hash design.
- Use one consistent recovery-code alphabet in generation, UI examples, and server validation so every displayed code can be confirmed.
- Generate a cryptographically random CSP nonce for every HTML response and apply that same response-specific nonce to the CSP header and inline style and script elements.
- Change recovery-code confirmation so it either validates without consuming a code or clearly states before submission and after success that the submitted code is consumed and must be discarded.