# TASKER REPORT — Iteration 3 · Step 7

## SUMMARY
- Raw tasks from Tasker: 6
- Effective task_list after retention: 6
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Replace email-only login with a server-side mock authentication mechanism that verifies pre-provisioned account credentials before issuing an MFA session; never create or select an account solely from a submitted email.","Bind identity verification to the authenticated account's pre-approved mock delivery channel, and do not reveal a usable identity code before account authentication succeeds.","Log simulated identity delivery codes, authenticator provisioning details and valid test verification values, and generated recovery codes with explicit browser-side console.log calls; do not log these values on the server or place them in URLs, errors, or browser storage.","Use documented deterministic mock identity and authenticator verification values, or a documented deterministic secret/code derivation, that the server accepts for repeatable testing while preserving single-use and lockout behavior where required.","Replace or repair the self-contained QR encoder so generated provisioning QR codes conform to the QR standard, including reserved function modules, valid alignment placement, masking, and error-correction/data placement.","Validate the provisioning URI against supported QR capacity before rendering; select a supported QR version/error-correction configuration or show a clear manual copy/setup fallback without rendering truncated QR data."]}
```

## PARSED_TASKS
- Replace email-only login with a server-side mock authentication mechanism that verifies pre-provisioned account credentials before issuing an MFA session; never create or select an account solely from a submitted email.
- Bind identity verification to the authenticated account's pre-approved mock delivery channel, and do not reveal a usable identity code before account authentication succeeds.
- Log simulated identity delivery codes, authenticator provisioning details and valid test verification values, and generated recovery codes with explicit browser-side console.log calls; do not log these values on the server or place them in URLs, errors, or browser storage.
- Use documented deterministic mock identity and authenticator verification values, or a documented deterministic secret/code derivation, that the server accepts for repeatable testing while preserving single-use and lockout behavior where required.
- Replace or repair the self-contained QR encoder so generated provisioning QR codes conform to the QR standard, including reserved function modules, valid alignment placement, masking, and error-correction/data placement.
- Validate the provisioning URI against supported QR capacity before rendering; select a supported QR version/error-correction configuration or show a clear manual copy/setup fallback without rendering truncated QR data.