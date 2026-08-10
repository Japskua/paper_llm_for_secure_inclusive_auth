## SUMMARY

The artifact is a strong single-file Bun SPA implementation with substantial server-side security controls, responsive mobile UI, simulated browser-side code logging, TLS configuration, CSRF protection, session controls, encrypted OTP secret storage, and hashed recovery codes. However, it cannot be accepted because the custom QR generator contains a concrete masking defect that can produce invalid/unscannable QR codes, the owner-code screen does not let the user re-request a code after reaching the entry screen, and development-mode persisted encrypted MFA state becomes unreadable after a server restart.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun implementation with no frameworks, build tools, external assets, or external network calls.**  
  The HTML, CSS, browser JavaScript, API implementation, persistence logic, and Bun TLS server are all contained in `app.ts`. The client uses vanilla browser APIs only.

- **PASS — Bun serves the SPA over TLS using the required local certificates.**  
  `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`.

- **PASS — Mobile-responsive, readable, dyslexia-conscious interface.**  
  The app includes a mobile viewport tag, constrained mobile-width shell, generous spacing, large controls, plain wording, input examples, no animation, persistent hints, and prominent step/action presentation.

- **FAIL — QR-code authenticator provisioning must provide a working QR code.**  
  The custom QR generator’s mask logic incorrectly treats large data regions as functional modules. In `apply()`, the alignment-pattern conditions for the centers around `(50, 28)` and `(28, 50)` omit upper bounds:
  ```js
  (x>=A[2]-2&&y>=A[1]-2)
  (x>=A[1]-2&&y>=A[2]-2)
  ```
  These conditions affect broad lower/right areas rather than only 5×5 alignment patterns. Those data modules are not masked even though the selected QR mask declares that they are, so scanners will unmask them incorrectly. The QR can therefore be invalid or decode to corrupted content.

- **PASS — Manual authenticator setup is supported.**  
  The provisioning secret is displayed in a readonly field and can be copied. The user may use this key instead of scanning the QR code.

- **PASS — Simulated OTP and recovery codes are returned to the UI and logged in the browser.**  
  Owner and identity codes are returned as `testCode`, recovery codes are returned in API responses, and the browser invokes `console.log()` through `demoLog()`.

- **PASS — OTP verification works during a running server session.**  
  Owner and identity codes are time-bound, single-use, and verified server-side. TOTP verification calculates valid TOTP windows server-side and prevents reuse of accepted time steps.

- **FAIL — Users must be able to re-request codes without penalty at every relevant step.**  
  After pressing “Send owner approval code,” the user reaches `ownerVerify()`. That screen says, “You may request a new code without penalty,” and server errors instruct the user to “Send a new code,” but there is no “Send a new code” button or other route back to `/api/auth/owner`. This is both a UX inconsistency and a functional dead end for expired owner codes.

- **PASS — Recovery-code flow supports reveal, hide, copy, replacement, and single-use redemption.**  
  Recovery codes can be generated, logged, copied, hidden/revealed in page memory, regenerated after confirmation, and are removed after successful verification.

- **PASS — Server-side authorization and IDOR protections are substantially implemented.**  
  Requests rely on the HttpOnly session cookie rather than a caller-controlled account identifier. The server checks `s.userId === USER.id` before MFA settings operations and does not expose routes accepting arbitrary user IDs.

- **PASS — CSRF protection is applied to authenticated state-changing API requests.**  
  Authenticated POST routes require the per-session `X-CSRF-Token`. Session cookies are `SameSite=Strict`. Cross-origin JSON requests are rejected by origin validation.

- **PASS — Secure headers and restrictive CORS are configured.**  
  The application sets CSP with nonce-based scripts/styles and `frame-ancestors 'none'`, HSTS, `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, and no-store caching. CORS only reflects explicitly allowed local TLS origins.

- **PASS — Session security controls are present.**  
  Session IDs are cryptographically random, are rotated after owner-code verification, have idle and absolute expiry checks, are invalidated on logout, and are issued in `HttpOnly; Secure; SameSite=Strict` cookies.

- **PASS — Verification protections are present.**  
  Owner, identity, TOTP, and recovery verification attempts are rate-limited with a five-failure lockout. Email/OTP/recovery-code input is validated server-side. Challenges expire after ten minutes and are marked used after success.

- **PASS — Secrets are not stored in browser storage or exposed in URL parameters/logs.**  
  No `localStorage`, `sessionStorage`, or non-HttpOnly cookie is used for secrets or sessions. Provisioning URIs are not placed into URLs. The browser logs simulated codes but does not log the TOTP seed.

- **FAIL — Persisted encrypted MFA state remains usable in the supplied development configuration.**  
  In non-production mode, `MFA_MASTER_KEY` and `MFA_HASH_PEPPER` are generated randomly at startup:
  ```ts
  masterMaterial ||= token(48);
  pepper ||= token(48);
  ```
  Yet `mfa-store.json` persists `encryptedSecret` and recovery-code hashes. After a server restart, the new key cannot decrypt previously stored OTP secrets, and the new pepper cannot validate previously stored recovery hashes. Existing MFA verification then fails, commonly producing a generic 500 response during decryption, while re-provisioning is blocked because `encryptedSecret` is already set.

- **PASS — Error handling avoids verbose stack traces.**  
  The top-level request handler returns a generic error response instead of leaking stack traces or sensitive values.

## FAILING_ITEMS

- The custom QR encoder has incorrect functional-module masking around alignment patterns. This can make the authenticator provisioning QR code unscannable or encode corrupted data.
- The owner approval-code entry screen has no resend/re-request action, despite the text promising it and errors instructing the user to do so.
- Development-mode ephemeral cryptographic keys are incompatible with the persisted `mfa-store.json` state. Restarting the server breaks existing enrolled MFA secrets and recovery-code verification.

## NEW_TASKS

1. Replace or correct the QR masking implementation so only true QR functional modules are excluded from mask application; validate generated `otpauth://` QR output with standard QR scanner/decoder tests.
2. Add a visible “Send a new owner approval code” secondary action to `ownerVerify()` that calls `/api/auth/owner`, logs the replacement code in the browser, and clearly states that the previous code no longer works.
3. Make persisted development data cryptographically usable across restarts: require stable development keys via environment variables, persist a development-only key safely outside account data, or clear/reset incompatible development state on startup with an explicit non-production notice.

## DECISION

**FAIL**