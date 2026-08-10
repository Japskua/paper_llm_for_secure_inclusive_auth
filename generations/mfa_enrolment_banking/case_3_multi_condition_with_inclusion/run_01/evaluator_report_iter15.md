## SUMMARY

The artifact is a single-file Bun HTTPS SPA with a functional sign-in, TOTP provisioning, QR/secret reveal and copy controls, OTP verification, recovery-code generation, session handling, CSRF checks, and security headers. Most core enrolment functionality is implemented well. However, it does not implement recovery-code verification or consumption, despite presenting recovery codes as usable one-time codes. This leaves the claimed backup-code behavior and associated verification rate-limiting/lockout incomplete.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no frameworks, bundlers, external assets, or network calls.**  
  The server, HTML, CSS, client JavaScript, and QR implementation are all contained in `app.ts`. Bun serves the page directly over TLS.

- **PASS — HTTPS/TLS and required security headers are configured.**  
  `Bun.serve` uses `certs/cert.pem` and `certs/key.pem`. Responses include CSP with nonces, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, referrer policy, permissions policy, and no-store caching.

- **PASS — Session cookies and session lifecycle controls are implemented.**  
  Session cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`. A new session token is generated at sign-in, existing account sessions are removed, idle and absolute expirations are checked, and logout invalidates the server-side session and expires the cookie.

- **PASS — Server-side authorization and IDOR protections are implemented for MFA endpoints.**  
  MFA endpoints derive the account from the authenticated server-side session via `owner(r)` and do not accept a caller-controlled account/user ID. A client cannot select another account by manipulating an identifier.

- **PASS — CSRF and same-origin protections are implemented for authenticated state changes.**  
  Authenticated POST endpoints require both a valid `Origin` and the per-session `X-CSRF-Token`. The sign-in endpoint also enforces the expected HTTPS same-origin `Origin`.

- **PASS — TOTP provisioning and enrolment verification work.**  
  A cryptographically random Base32 secret is generated, stored encrypted with AES-GCM, converted into an `otpauth://` URI, and verified using RFC-style HMAC-SHA-1 TOTP generation. The OTP is time-bound and the enrolment OTP cannot be reused once accepted.

- **PASS — TOTP verification attempts are validated and protected by lockout.**  
  OTP input is restricted to six digits, invalid input receives a clear fix-oriented message, and repeated failures lock the OTP verification flow for five minutes.

- **FAIL — Recovery codes are not actually usable or enforceably single-use.**  
  Recovery codes are generated and HMACed at rest, but there is no endpoint or UI to submit a recovery code. Consequently, the application cannot verify a recovery code, mark it consumed, reject replay, or apply the defined `recoveryFailures` / `recoveryLocked` controls. The UI statement “Each code works once” is not implemented.

- **FAIL — Verification-code rate limiting/lockout is incomplete.**  
  OTP verification has a lockout, but recovery-code verification does not exist even though account fields for recovery failures and recovery lockout are declared. Therefore the requirement to rate-limit and lock out repeated failed verification attempts is incomplete for the offered recovery mechanism.

- **PASS — Secrets and recovery codes are generated and stored securely enough for the mock.**  
  TOTP secrets use cryptographic randomness and are encrypted at rest with AES-GCM. Recovery codes use cryptographic randomness and only HMAC values are stored after issuance. Session tokens are cryptographically random.

- **PASS — Sensitive values are not put into URLs, server logs, browser storage, or error output.**  
  There is no use of `localStorage` or `sessionStorage`; session IDs are in HttpOnly cookies; the provisioning URI is not placed in the browser address bar; server error handling is generic; and server-side code does not log secrets, OTPs, recovery codes, or session tokens. Browser `console.log` output of deterministic mock OTP/recovery values is explicitly required by the specification.

- **PASS — Mobile and dyslexia-aware UX is substantially addressed.**  
  The UI has mobile sizing, generous controls, readable typography, spacing, plain-language instructions, short examples, stable non-animated content, visible step progression, one primary action per main step, help disclosures, no reading timer, copy controls, QR support, reveal/hide behavior, and clear error text.

- **PARTIAL / FAIL — Semantic input labeling is incomplete.**  
  Input labels are visually present but are not associated with their inputs using `for` and matching `id` values. This weakens semantic HTML and assistive-technology usability.

## FAILING_ITEMS

- Recovery codes are displayed and described as one-time usable codes, but no server endpoint accepts a recovery code.
- Recovery code hashes are never matched against submitted values, consumed, or removed after use.
- `used`, `recoveryFailures`, and `recoveryLocked` are declared but unused, showing that recovery verification and its anti-brute-force controls are unfinished.
- The offered recovery mechanism therefore does not satisfy the requirement that verification codes be single-use and protected against repeated failed attempts.
- Client-side `<label>` elements do not use `for` attributes tied to the corresponding input IDs, reducing semantic/accessibility quality.

## NEW_TASKS

1. Add a CSRF-protected, authenticated recovery-code verification endpoint that validates the submitted `AAAAA-BBBBB` code, compares its HMAC against the account’s stored recovery-code HMACs using constant-time comparison, and consumes the matching code immediately on success.

2. Apply recovery-code validation controls in that endpoint: reject malformed input, increment `recoveryFailures` on invalid or already-used codes, lock the recovery verification path after `MAX_FAILURES`, reset failure state after a successful verification, and return clear user-facing error messages.

3. Add a mobile recovery-code verification screen or account-flow entry point that allows a user to manually submit a recovery code, supports `autocomplete="one-time-code"`, gives an input example, and plainly confirms successful use or explains a retry/lockout state.

4. Associate every visible form label with its input by adding stable input `id` values and corresponding `for` attributes, including email, password, and OTP/recovery-code inputs.

## DECISION

**FAIL**