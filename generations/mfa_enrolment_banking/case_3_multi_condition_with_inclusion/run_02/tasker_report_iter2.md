# TASKER REPORT — Iteration 2 · Step 4

## SUMMARY
- Raw tasks from Tasker: 9
- Effective task_list after retention: 9
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Require certs/cert.pem and certs/key.pem at startup, serve only through Bun TLS, and fail closed with a generic startup error when certificates are unavailable.","Replace arbitrary-email login with a mock identity-verification flow that creates a Marcus session only for the verified account owner.","Protect /api/login with CSRF validation or strict server-side Origin validation before creating an authenticated session.","Replace qrSvg() with a self-contained standards-compliant QR encoder that encodes the returned otpauth:// provisioning URI and is scannable by authenticator applications.","Verify authenticator entries using a real TOTP derived from the provisioned secret or a cryptographically random per-provisioning mock OTP; log the test value only in the browser console.","Store each recovery code with a unique salt and slow KDF, and add a CSRF-protected endpoint that atomically verifies and consumes a recovery code once.","Add setup-secret hide/reveal controls and an explicit recovery-code regeneration action that clearly states regenerated codes replace prior codes.","Keep the active provisioning and verification state after an invalid OTP so retry returns to the same code-entry screen without generating a new secret.","Remove the persistent visible sensitive-data log panel; retain required mock setup, OTP, and recovery-value output only in the browser developer console."]}
```

## PARSED_TASKS
- Require certs/cert.pem and certs/key.pem at startup, serve only through Bun TLS, and fail closed with a generic startup error when certificates are unavailable.
- Replace arbitrary-email login with a mock identity-verification flow that creates a Marcus session only for the verified account owner.
- Protect /api/login with CSRF validation or strict server-side Origin validation before creating an authenticated session.
- Replace qrSvg() with a self-contained standards-compliant QR encoder that encodes the returned otpauth:// provisioning URI and is scannable by authenticator applications.
- Verify authenticator entries using a real TOTP derived from the provisioned secret or a cryptographically random per-provisioning mock OTP; log the test value only in the browser console.
- Store each recovery code with a unique salt and slow KDF, and add a CSRF-protected endpoint that atomically verifies and consumes a recovery code once.
- Add setup-secret hide/reveal controls and an explicit recovery-code regeneration action that clearly states regenerated codes replace prior codes.
- Keep the active provisioning and verification state after an invalid OTP so retry returns to the same code-entry screen without generating a new secret.
- Remove the persistent visible sensitive-data log panel; retain required mock setup, OTP, and recovery-value output only in the browser developer console.