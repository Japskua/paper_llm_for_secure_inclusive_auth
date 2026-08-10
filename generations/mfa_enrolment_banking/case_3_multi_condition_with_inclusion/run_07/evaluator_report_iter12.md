## SUMMARY

The artifact is a strong single-file Bun HTTPS MFA enrolment SPA with substantial security controls, accessible mobile-focused UX, functioning simulated authenticator flows, QR/manual setup options, CSRF/session protections, encryption/hashing, and browser-console test values. However, it is not runnable as delivered unless an undocumented external `MFA_DEMO_PIN` environment variable is supplied: it intentionally exits at startup when that variable is absent. This prevents the required deterministic mock enrolment flow from working out of the box.

## FUNCTIONAL_CHECK

- **FAIL — The app provides a runnable simulated MFA enrolment flow.**  
  The server terminates during startup unless `MFA_DEMO_PIN` is externally configured:
  ```ts
  if (!PIN || !/^\d{4,12}$/.test(PIN)) {
    console.error("Configuration error.");
    process.exit(1);
  }
  ```
  No deterministic demo PIN is supplied in the single-file artifact, displayed to the tester, or otherwise documented in the UI. Therefore, the provided app cannot be started and exercised as-is.

- **PASS — Single-file Bun implementation with no frameworks, bundlers, compilation pipeline, or external network calls.**  
  HTML, CSS, client JavaScript, server logic, and API routing are all contained in `app.ts`. It uses Bun APIs directly and does not fetch external assets or services.

- **PASS — HTTPS/TLS certificate configuration is present.**  
  `Bun.serve` uses `certs/cert.pem` and `certs/key.pem` as required. The service is configured as TLS-only.

- **PASS — Mobile-responsive, dyslexia-conscious UI is implemented.**  
  The page uses a narrow mobile layout, generous spacing, large form controls, readable font fallbacks, increased letter/line spacing, concise copy, examples for expected formats, status messages, icons, and no animated or time-pressured UI.

- **PASS — One predictable MFA enrolment flow is present.**  
  The UI guides users through sign-in, identity confirmation, authenticator setup, OTP verification, backup-code generation, backup-code validation, completion, and logout.

- **PASS — QR and manual authenticator provisioning are supported.**  
  The setup endpoint returns a standard `otpauth://` URI and Base32 secret. The UI renders a QR canvas, offers a setup-link copy button, presents the manual key, and offers a manual-key copy button.

- **PASS — OTP verification works and is time-bound/single-use.**  
  Server-side TOTP validation accepts only current/adjacent 30-second windows, and accepted time steps are recorded in `usedSteps`, preventing reuse.

- **PASS — Simulated test OTP values are returned to the browser and logged in the browser console.**  
  The mock OTP endpoints return a practice code, and `testLog()` writes it with `console.log`. The code is single-use and expires after ten minutes.

- **PASS — Backup codes are securely generated, presented, copied, and verified as single-use.**  
  Eight codes are generated using Web Crypto RNG, shown in the UI, available for clipboard copy/printing, logged to the browser console for the academic test, stored only as salted/peppered SHA-256 hashes, and removed after successful verification.

- **PASS — The OTP secret is encrypted at rest and recovery codes are hashed.**  
  The TOTP secret is encrypted with AES-GCM before placement in server state. Backup codes are stored as SHA-256 hashes incorporating a cryptographically generated pepper.

- **PASS — Session ownership and IDOR defenses are implemented for the demo account model.**  
  Every protected endpoint resolves the authenticated session server-side, verifies its account ownership, and does not accept client-supplied account/session/user identifiers. Requests containing `accountId`, `userId`, or `sessionId` are rejected.

- **PASS — CSRF protections are applied to state-changing protected requests.**  
  Protected POST requests require both a same-origin HTTPS `Origin` header and a matching `X-CSRF-Token`. The session cookie uses `SameSite=Strict`.

- **PASS — Secure session handling is implemented.**  
  Sessions use high-entropy random identifiers, are regenerated at authentication, have idle and absolute expiry limits, are invalidated at logout, and are delivered only in `HttpOnly; Secure; SameSite=Strict` cookies.

- **PASS — Rate limiting and temporary lockout are implemented.**  
  Authentication and MFA-code failures are counted. Repeated failures trigger a five-minute lockout with a clear recovery message.

- **PASS — Security headers and CORS restrictions are implemented.**  
  Responses include CSP with per-page nonce, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, and restrictive permissions policy. No permissive CORS headers are sent.

- **PASS — Input validation and output encoding are implemented.**  
  Email, phone, OTP, recovery-code, and body size/shape checks are present. Dynamic browser-rendered values are escaped or inserted with `textContent`; server messages are not rendered via unsafe HTML interpolation.

- **PASS — Errors are generic and user-facing messages are specific without exposing stack traces or secrets.**  
  The top-level server handler returns a generic error response. Client-side errors use plain-language messages explaining what to do next.

## FAILING_ITEMS

- **The application exits instead of serving the enrolment system when `MFA_DEMO_PIN` is not set.**  
  This makes the submitted single-file artifact non-functional by default and fails the requirement for deterministic simulated values that can be used to test the enrolment flow. A tester cannot know or use the account PIN from the supplied artifact without separately discovering and configuring an environment variable.

## NEW_TASKS

1. **Make the demo authentication credential deterministic and usable without external configuration.**  
   Provide a safe deterministic fallback demo PIN in `app.ts` when `MFA_DEMO_PIN` is absent, or otherwise implement an in-app deterministic test credential mechanism. Keep environment override support if desired, validate the resulting PIN, and ensure the server no longer exits solely because the optional demo environment variable was omitted.

## DECISION

FAIL