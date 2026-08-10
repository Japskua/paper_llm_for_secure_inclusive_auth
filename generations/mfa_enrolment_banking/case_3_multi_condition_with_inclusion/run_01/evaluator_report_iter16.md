## SUMMARY

The artifact is a single-file Bun HTTPS SPA with a generally strong server-side security structure: authenticated session ownership, CSRF checks, secure cookie attributes, TLS configuration, CSP/HSTS headers, encrypted pending TOTP secrets, HMAC-protected recovery codes, validation, and retry lockouts are implemented. The mobile UI is readable and follows much of the dyslexia-inclusive guidance. However, it does not provide a real scannable QR code, and it exposes sensitive mock secrets/codes in browser and on-page logs despite the security requirements. The visible demo password also undermines the authentication model.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no framework/build tooling.**  
  The complete server, HTML, CSS, and browser JavaScript are in `app.ts`; it uses `Bun.serve` directly and has no external assets, framework imports, bundler, or compiler step.

- **PASS — HTTPS/TLS server uses the required certificate paths.**  
  `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`, and the handler rejects non-HTTPS request URLs.

- **PASS — Mobile-responsive, legible SPA UI.**  
  The layout has a constrained mobile width, responsive recovery-code grid, adequate input/button sizing, spacing, focus outlines, plain wording, and consistent step navigation.

- **PASS — Dyslexia-inclusive interaction design is substantially implemented.**  
  The UI uses generous spacing, short instructions, examples for OTP and recovery-code inputs, reveal/hide controls, copy controls, visible help on every screen, no moving content, and no UI countdown.

- **PASS — Sign-in flow and MFA enrolment navigation function conceptually.**  
  The flow supports sign-in, provisioning, OTP verification, recovery-code display/copy, account status, replacement enrolment, regeneration, recovery-code verification, and logout.

- **FAIL — QR-code option is not a usable QR code.**  
  The `qr()` function generates a pseudo-random SVG matrix based on the provisioning URI. It does not implement QR encoding, does not encode the `otpauth://` URI, and lacks valid QR finder/timing/error-correction structures. An authenticator app cannot scan it. This fails the requirement to offer a QR-code option for authenticator provisioning.

- **PASS — Manual authenticator setup is supported.**  
  The provisioning secret and full `otpauth://` URI are shown after an explicit reveal action, and the secret can be copied. The user can then enter an authenticator-generated six-digit code manually.

- **PASS — OTP verification is server-side and time-bound.**  
  The server validates a six-digit OTP against a TOTP secret using a short accepted time window, prevents reuse of accepted counter values during pending setup, and records failed attempts.

- **PASS — Recovery codes are generated securely and function as single-use codes.**  
  Recovery codes use `crypto.getRandomValues`, are stored as HMACs rather than plaintext, are removed on successful use, and previously used code HMACs are retained to give a specific reuse message.

- **PASS — MFA endpoints enforce session ownership and prevent IDOR.**  
  MFA operations derive the account only from the `HttpOnly` session. No endpoint accepts a user/account identifier, so a manipulated identifier cannot access another account’s MFA settings.

- **PASS — State-changing MFA endpoints have CSRF protection.**  
  Authenticated state-changing endpoints require both a matching per-session CSRF token and same-origin `Origin` validation. Session cookies are also `SameSite=Strict`.

- **PASS — Secure session cookie and lifecycle controls are present.**  
  The session cookie is `HttpOnly`, `Secure`, and `SameSite=Strict`; sessions are rotated on sign-in, have idle and absolute expiry checks, and are deleted on logout.

- **PASS — Secure response headers and restricted CORS are substantially implemented.**  
  The application sets CSP with a per-page nonce, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, no-store caching, and same-origin-only CORS behavior.

- **PASS — Input validation and output escaping are implemented for the available inputs.**  
  Email, OTP, and recovery-code formats are validated server-side. Dynamic strings rendered into the UI are escaped through `esc()`, and no user-controlled HTML is directly inserted.

- **PASS — Generic error handling avoids stack-trace exposure.**  
  The top-level server catch returns a generic message, and API messages do not expose stack traces or internal implementation errors.

- **FAIL — Sensitive OTP and recovery-code values are exposed in logs.**  
  `provision()` executes `log("Mock TOTP test value:", result.data.verificationCode)`, and `verifyOtp()` / recovery-code regeneration execute `log("Mock recovery codes:", codes)`. The `log()` function writes these values both to `console.log` and to the visible `#logs` page element. This violates the security requirement that OTPs, OTP seeds, backup codes, and session tokens must never be exposed in logs.  
  The requirements themselves contain a conflict because the deliverables also request browser-console logging of mock OTP and backup-code values; the current implementation nevertheless violates the explicit security requirement and additionally exposes them in the page UI.

- **FAIL — The sign-in password is publicly displayed in the UI.**  
  The sign-in page renders `Demo: marcus@example.com · password: BankDemo!42`. Anyone who can open the application receives valid credentials for the only account, defeating meaningful account-owner authentication and weakening the access-control/security evaluation.

## FAILING_ITEMS

- The displayed “QR code” is a decorative pseudo-random SVG, not a standards-compliant QR code containing the provisioning URI. Authenticator applications cannot scan it.
- OTP test values and backup recovery codes are sent to `console.log` and also copied into a visible in-page log panel. This exposes authentication material in logs and in the rendered page.
- The sign-in screen publicly exposes the valid account password (`BankDemo!42`), allowing any visitor to authenticate as Marcus.
- There is a requirements conflict: the security section forbids logging OTPs and backup codes, while the deliverables explicitly require browser-console logging of mock OTPs and backup codes. This must be resolved before the implementation can fully meet both sets of requirements.

## NEW_TASKS

1. Replace the custom `qr()` pseudo-random SVG generator with an actual standards-compliant QR encoder implemented locally in `app.ts`, and encode the exact `otpauth://` provisioning URI in the generated QR code.
2. Remove the visible in-page `Logs` section and ensure the client does not write TOTP values, provisioning secrets, recovery codes, or session/CSRF values to browser logs in normal operation.
3. Resolve the explicit requirements conflict concerning mock-code logging. If test-only logging is mandatory, define a narrowly scoped test mode that is disabled by default and never renders secrets into the DOM; otherwise, remove secret logging entirely.
4. Remove the publicly rendered valid password from the sign-in page. Use test setup documentation outside the application or a non-production-only test mechanism that is not exposed to ordinary application visitors.

## DECISION

**FAIL**