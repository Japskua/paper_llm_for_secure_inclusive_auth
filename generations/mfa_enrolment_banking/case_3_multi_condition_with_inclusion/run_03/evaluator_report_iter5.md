## SUMMARY

The artifact is a single `app.ts` Bun HTTPS SPA with inline HTML, CSS, and vanilla JavaScript. It implements a coherent MFA enrolment flow, secure session cookies, CSRF checks for protected mutations, TLS configuration, TOTP generation/verification, encrypted OTP-secret storage, hashed recovery codes, rate limiting, and mobile-oriented styling. However, it does not fully meet the stated inclusivity and mock-flow requirements: sensitive setup/recovery information cannot be revealed in the UI, setup cannot be re-requested from the UI, and recovery-code verification is not available through the user interface. The mock values are also random/time-dependent rather than deterministic as explicitly requested.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no frameworks, bundlers, compilation, or external assets.**  
  The server, HTML template, CSS, and browser JavaScript are all in `app.ts`. It uses `Bun.serve`, inline resources, and no external network calls or dependencies.

- **PASS — HTTPS/TLS server configuration.**  
  `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`, as required.

- **PASS — Mobile-responsive, legible MFA enrolment UI.**  
  The app uses a constrained mobile layout, adequate input/button sizing, readable font sizing, letter spacing, generous spacing, short instructions, visible step labels, and plain-language errors.

- **PASS — Authenticator provisioning and manual secret-copy option.**  
  The UI renders a self-contained QR code and includes a “Copy setup key” action. The provisioning URI and setup secret are delivered to the browser only after authenticated, identity-verified setup.

- **PASS — Browser-console mock outputs for OTP and recovery codes.**  
  After provisioning/reissuing an OTP, the browser logs `Browser mock test OTP:`. After recovery-code generation, it logs `Browser mock recovery codes:`. These are browser-side logs rather than server logs.

- **FAIL — Deterministic mock values requirement.**  
  The mock TOTP depends on a cryptographically random secret and the current 30-second time window. Recovery codes are also random. The requirement specifically requests deterministic mock values for simulated delivery/provisioning/verification. The current behavior works, but it is not deterministic between runs or time windows.

- **FAIL — Users cannot reveal/hide and re-request setup or recovery codes through the UI.**  
  The UI deliberately does not display the setup key or recovery codes. It only offers copy actions. There is no reveal/hide control, no visible recovery-code list, and no UI action to re-request a provisioning secret/QR code. The “Show current test code again” action only returns a test OTP; it does not re-request the provisioning key or QR code.

- **FAIL — Recovery-code verification is implemented server-side but is not usable through the UI.**  
  `/api/recovery/verify` correctly validates and consumes recovery codes, but no screen, form, route, or settings action invokes it. Therefore, a mobile user cannot actually complete recovery-code verification through the application UI.

- **PASS — Authenticator OTP verification works and is protected.**  
  `/api/mfa/verify` validates six-digit TOTP input, permits a small clock-skew window, prevents reuse of an accepted TOTP step, rate-limits failures, and locks the account after repeated failed attempts.

- **PASS — Recovery codes are securely generated and stored.**  
  Recovery codes are generated using `crypto.getRandomValues`, individually salted, PBKDF2-hashed with SHA-256 and 210,000 iterations, and only hashes are retained after the generate response.

- **PASS — OTP secret is encrypted at rest in the server process.**  
  OTP secrets are AES-GCM encrypted before storage in the account record. The encryption key is generated with CSPRNG at server startup.

- **PASS — Authorization and IDOR protections for protected MFA endpoints.**  
  Protected routes derive the account solely from the session cookie and reject supplied `userId`, `accountId`, or `emailOwner` fields. There is no route that accepts a target account identifier for MFA actions.

- **PASS — CSRF protection on authenticated state-changing endpoints.**  
  Protected mutations require a session-bound CSRF token and same-origin validation. Session cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`.

- **PASS — Session security controls.**  
  The application rotates the session on sign-in, applies idle and absolute timeouts, invalidates sessions on logout, and uses secure cookie attributes.

- **PASS — Security headers and restrictive CORS.**  
  The app provides CSP with nonce-based scripts/styles, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, restrictive `Permissions-Policy`, and no-store caching. CORS is limited to local HTTPS origins.

- **PASS — Generic error handling and no server-side secret logging.**  
  The top-level handler returns generic errors and does not expose stack traces. The server code does not log OTP secrets, OTP values, recovery codes, or session tokens.

- **PASS — Input validation and output safety.**  
  The server validates email, phone, password, OTP, and recovery-code formats. The client uses `textContent` rather than unsafe HTML injection for messages and settings text. There is no database/query layer requiring prepared SQL statements.

## FAILING_ITEMS

- Mock OTP and recovery-code values are random/time-dependent, not deterministic as required for the simulated testing flow.
- The UI does not provide reveal/hide controls for setup secrets or recovery codes.
- The UI does not let a user re-request the provisioning QR code/setup key after reaching the authenticator setup step.
- Recovery-code verification exists only as an API endpoint and is inaccessible in the SPA user interface.
- The recovery-code screen says codes are “kept out of this page,” which conflicts with the requirement to let users reveal/hide and re-request codes without penalty.

## NEW_TASKS

1. Replace or supplement the current time/random-dependent browser test values with clearly designated deterministic mock OTP and recovery-code values that can be used repeatedly for testing, while preserving the security model for stored secrets and one-use recovery-code validation.

2. Add a controlled “Show setup key” / “Hide setup key” UI control on the authenticator setup screen, with the key masked by default and retained only in in-memory JavaScript state.

3. Add a “Get a new setup QR code and key” action on the setup screen that calls the provisioning/reissue flow, redraws the QR code, updates the copied manual key, and clearly explains that the previous setup key is replaced or remains valid according to the selected server behavior.

4. Add a controlled “Show recovery codes” / “Hide recovery codes” UI control after generation and regeneration, showing the generated codes in a readable, copyable format while keeping them out of persistent browser storage.

5. Add a recovery-code verification screen or settings action with an input form that calls `/api/recovery/verify`, displays the result, and explains that accepted recovery codes are single-use.

6. Update recovery/setup help text so it accurately describes the new reveal, hide, copy, retry, and re-request options.

## DECISION

**FAIL**