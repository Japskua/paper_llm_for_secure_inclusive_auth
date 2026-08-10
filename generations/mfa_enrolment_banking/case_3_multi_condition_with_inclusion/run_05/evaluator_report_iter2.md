## SUMMARY

The artifact is a single-file Bun HTTPS SPA with a generally strong structure: secure cookies, CSRF checks, session rotation, encrypted TOTP seed storage, hashed recovery-code storage, restrictive headers, responsive mobile UI, and browser-console mock delivery output are implemented. However, it does not fully meet the security and functional requirements because authenticator OTP failures are not rate-limited, provisioning/recovery secrets are fixed rather than securely generated, the QR encoder does not generate a valid Version 8 QR code, and several displayed recovery codes cannot be confirmed due to a validation mismatch.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no framework, build tool, external assets, or compilation step.**  
  The HTML, CSS, browser JavaScript, API logic, and Bun server are contained in `app.ts`. It uses `Bun.serve` and inline client code.

- **PASS — HTTPS/TLS is configured using the required certificate locations.**  
  `Bun.serve` loads `certs/cert.pem` and `certs/key.pem`, and session cookies are marked `Secure`.

- **PASS — Responsive, dyslexia-conscious mobile UI is substantially implemented.**  
  The UI uses a narrow mobile shell, readable font fallbacks, generous line/letter spacing, plain-language text, large controls, short hints/examples, no animation, a prominent primary action, and help content on each screen.

- **PASS — The sign-in, identity-code, authenticator, backup-code, completion, and logout flow is wired through functional internal API calls.**  
  Client navigation is state-driven and each relevant button calls a corresponding endpoint. Identity verification, provisioning, TOTP verification, recovery confirmation, and logout paths exist.

- **PASS — Mock delivery details are returned to the client and logged in the browser.**  
  The client logs identity codes, provisioning secrets, test OTPs, and recovery codes with `console.log`, as required for testing. The server does not log those secrets.

- **FAIL — The QR code option is not reliably functional.**  
  `drawQR()` claims to produce a “QR version 8-L” code, but Version 8 QR codes require Version Information bits. The encoder does not write those mandatory bits. It also fills all unreserved cells as data, including locations that should hold version information. A QR scanner may therefore reject or misread the displayed provisioning code.

- **PASS — Manual authenticator-secret entry is supported.**  
  The provisioning screen displays/copies a secret and permits it to be manually pasted into the input. The server validates it against the encrypted session secret.

- **FAIL — Recovery-code confirmation rejects some recovery codes that the UI displays.**  
  The UI displays codes including `RIVER-48291`, `STONE-19584`, `FIELD-94316`, and `BRICK-86193`, but `/api/recovery/confirm` only accepts `[A-Z2-9]`, excluding `1`. Those valid-looking displayed codes produce a format error instead of being accepted.

- **PASS — Server-side authorization and session ownership are generally enforced for protected MFA operations.**  
  Protected endpoints call `owner(request)`, require an authenticated account-bearing session, do not accept user/account identifiers from requests, and do not expose arbitrary account selection.

- **PASS — CSRF protection is implemented for state-changing actions.**  
  State-changing POST endpoints require the server-issued CSRF token, and cookies use `SameSite=Strict`. Requests from untrusted `Origin` values are rejected.

- **PASS — Secure response headers and cookie attributes are substantially present.**  
  The application sets CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, restrictive CORS handling, `Cache-Control: no-store`, and `HttpOnly; Secure; SameSite=Strict` session cookies.

- **FAIL — CSP nonce handling is insecure because the nonce is static.**  
  Both the CSP header and document use fixed values (`nonce-mfa-client` and `nonce-mfa-style`) for every response. CSP nonces must be generated unpredictably per response. A known fixed nonce weakens CSP protection against injected inline script/style content.

- **FAIL — TOTP authenticator verification has no failed-attempt rate limiting or lockout.**  
  `/api/otp/verify` accepts unlimited incorrect codes. Unlike identity verification and recovery-code confirmation, it has no attempt counter, lockout timestamp, or `429` response. This fails the requirement to rate-limit and lock out repeated failed verification attempts.

- **FAIL — OTP shared secrets and backup codes are hard-coded rather than generated with a cryptographically secure RNG.**  
  `DEMO_SECRET` and `DEMO_RECOVERY_CODES` are constants reused for every session. This means different users/sessions receive the same authenticator seed and recovery-code set, violating the requirement for securely generated secrets and backup codes.

- **FAIL — Recovery-code hashing is insufficiently protected for the low-entropy fixed code set.**  
  Recovery codes are stored as unsalted SHA-256 hashes via `hash(code)`. Because the codes are fixed and have constrained format, hashes are susceptible to offline guessing if session storage is compromised. Per-code random values and a slow password-hashing/KDF approach, or keyed hashing with securely generated high-entropy codes, should be used.

- **PASS — TOTP codes are time-based and replay-protected after successful use.**  
  The implementation computes RFC-style TOTP values by 30-second step, permits a small clock-skew window, and records accepted TOTP steps in `usedTotpSteps` to prevent replay.

- **PASS — Identity codes are single-use, time-bound, and rate-limited.**  
  Identity codes expire after 15 minutes, are marked used after success, and lock after five failed attempts.

- **PASS — Session lifecycle protections are substantially implemented.**  
  A new session identifier is created after sign-in, server-side idle and absolute session expiry are enforced, and logout deletes the server session and expires the cookie.

- **PASS — Input validation and output handling are mostly safe.**  
  API input is parsed as JSON, identifier/redirect fields are rejected, email/code formats are validated, and browser-rendered dynamic values are escaped or assigned using `textContent`.

- **FAIL — The recovery-code confirmation action silently consumes a backup code.**  
  The UI tells the user “I saved a code,” but the server deletes the submitted recovery code. The user is not told that this confirmation step spends one of their backup codes. This is misleading and conflicts with the requirement for clear confirmation of what happened and what to do next.

## FAILING_ITEMS

- The custom QR encoder does not write mandatory Version 8 QR version-information modules, so the QR provisioning option is not dependable.
- `/api/otp/verify` lacks failed-attempt counting, throttling, and lockout.
- `DEMO_SECRET` is a fixed TOTP seed shared across all sessions.
- `DEMO_RECOVERY_CODES` are fixed and reused across all sessions.
- Recovery-code hashes use plain unsalted SHA-256 despite fixed/constrained recovery-code values.
- The recovery-code validator excludes `1`, while four displayed recovery codes contain `1`.
- CSP nonces are hard-coded rather than generated per HTML response.
- The backup-code confirmation flow deletes a code without informing the user that it will be consumed.

## NEW_TASKS

1. Replace or correct `drawQR()` so it produces standards-compliant QR codes for the provisioning URI, including all required Version 8 metadata; verify the rendered code scans successfully with a standard authenticator application.
2. Add per-session TOTP verification attempt tracking, a maximum-attempt threshold, and a lockout period to `/api/otp/verify`; return a clear `429` message with retry guidance.
3. Generate a unique TOTP secret for every provisioning request using `crypto.getRandomValues`, encrypt it at rest, and return/log the generated mock value only through the browser testing UI.
4. Generate a unique set of high-entropy recovery codes with `crypto.getRandomValues` for each successful MFA enrolment rather than using `DEMO_RECOVERY_CODES`.
5. Store recovery codes using a stronger at-rest design: generate sufficiently high-entropy codes and use a per-code salt with a suitable password-hashing/KDF approach, or a keyed server-side hash design.
6. Make recovery-code generation, displayed examples, and `/api/recovery/confirm` validation use one consistent character alphabet. Either permit `0`/`1` in validation or generate codes that exclude ambiguous characters.
7. Generate a cryptographically random CSP nonce for every HTML response and inject the same per-response nonce into the CSP header and the corresponding `<style>`/`<script>` tags.
8. Change the backup-code confirmation UX so it either validates without consuming a code, or clearly states before submission and in the result that the entered backup code has been used and should be discarded.

## DECISION

FAIL