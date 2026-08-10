# TASKER REPORT — Iteration 2 · Step 4

## SUMMARY
- Raw tasks from Tasker: 4
- Effective task_list after retention: 4
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Replace the pseudo-QR rendering with an in-file standards-compliant QR encoder for a real `otpauth://totp/...` URI containing issuer, account label, Base32 secret, algorithm, digits, and period. Show copyable manual Base32-secret and provisioning-URI options alongside the scannable QR code.","Add an authenticated, CSRF-protected endpoint that rotates and returns fresh authenticator setup details during the OTP stage. Add an OTP-screen action to request these details after refresh or expiry, with a clear confirmation and fresh mock values logged only in the browser console.","Require the identity stage and enforce active lockout checks on both identity verification and identity resend routes. Ensure resend cannot reset identity failure counters or bypass the five-minute failed-attempt lockout.","Make progress-bar rendering compatible with the nonce-based CSP by removing inline style attributes and JavaScript style-property mutations. Use predefined nonce-authorized CSS classes or another CSP-compliant mechanism to represent each progress width."]}
```

## PARSED_TASKS
- Replace the pseudo-QR rendering with an in-file standards-compliant QR encoder for a real otpauth://totp/... URI containing issuer, account label, Base32 secret, algorithm, digits, and period. Show copyable manual Base32-secret and provisioning-URI options alongside the scannable QR code.
- Add an authenticated, CSRF-protected endpoint that rotates and returns fresh authenticator setup details during the OTP stage. Add an OTP-screen action to request these details after refresh or expiry, with a clear confirmation and fresh mock values logged only in the browser console.
- Require the identity stage and enforce active lockout checks on both identity verification and identity resend routes. Ensure resend cannot reset identity failure counters or bypass the five-minute failed-attempt lockout.
- Make progress-bar rendering compatible with the nonce-based CSP by removing inline style attributes and JavaScript style-property mutations. Use predefined nonce-authorized CSS classes or another CSP-compliant mechanism to represent each progress width.