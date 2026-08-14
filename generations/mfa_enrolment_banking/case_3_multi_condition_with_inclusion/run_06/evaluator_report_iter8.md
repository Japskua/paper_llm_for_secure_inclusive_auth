## SUMMARY

The artifact is a single-file Bun HTTPS SPA with a strong mobile-focused MFA flow, browser-side mock logging, CSRF checks, session cookies, security headers, input validation, expiry, single-use challenge tracking, and rate limiting. The UI is generally accessible and functional. However, it does not meet all security requirements because authenticator material, OTPs, and recovery codes are hard-coded rather than cryptographically generated, and recovery-code “regeneration” produces the same codes, so previously saved recovery codes remain valid after replacement.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application without frameworks, bundlers, or external assets.**  
  The complete server, HTML, CSS, and vanilla browser JavaScript are contained in `app.ts`. It uses `Bun.serve`, inline HTML/CSS/JS, and does not reference external network assets.

- **PASS — HTTPS/TLS server configuration.**  
  Bun is configured with `certs/cert.pem` and `certs/key.pem`, and requests whose URL protocol is not HTTPS are rejected.

- **PASS — Mobile-responsive, legible MFA UI.**  
  The page uses a constrained mobile layout, responsive media rules, large inputs and buttons, generous spacing, readable line height, and a dyslexia-oriented font stack.

- **PASS — Accessible and low-reading-load enrolment flow.**  
  The flow uses short instructions, icons, examples, consistent steps, a help area, non-moving UI, clear errors, and one prominent primary action on each main screen.

- **PASS — Browser autofill and manual-entry support.**  
  Email/password inputs provide suitable `autocomplete` values; OTP fields use `autocomplete="one-time-code"`; QR provisioning is paired with a copyable manual setup key; recovery codes can be copied.

- **PASS — Mock values are returned to the browser UI and logged in the browser console.**  
  Identity OTPs, setup secrets, provisioning URIs, authenticator test codes, and backup codes are returned through API responses and logged with browser-side `console.log`, not server logging.

- **PASS — Identity and authenticator challenges are time-bound and single-use at the challenge level.**  
  `identityChallenge` and `authenticatorChallenge` contain `expires` and `used` fields. Verification rejects expired or used challenges.

- **PASS — MFA endpoints enforce session ownership and identity verification.**  
  The `owner()` and `verified()` helpers ensure endpoints derive the account from the authenticated session rather than accepting user/account IDs from the client. This prevents straightforward IDOR through manipulated identifiers.

- **PASS — State-changing endpoints use CSRF protection.**  
  Login, logout, identity sending/verification, authenticator setup/confirmation, recovery-code generation, and recovery-code verification check `X-CSRF-Token` against the session token. Session cookies are also `SameSite=Strict`.

- **PASS — Secure session cookie attributes and session management are mostly implemented.**  
  Session cookies are `HttpOnly`, `Secure`, `SameSite=Strict`, path-scoped, and have an absolute lifetime. Sessions enforce idle and absolute timeouts, are rotated on login, and are invalidated on logout.

- **PASS — Security response headers and CORS behavior are implemented.**  
  The app sets CSP with nonces, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, and restrictive permissions/cross-origin policies. It does not emit permissive CORS headers and rejects untrusted supplied origins.

- **PASS — Input validation and output handling are generally safe.**  
  Email, six-digit OTPs, and recovery-code formats are validated server-side. User-entered values are not interpolated into server-rendered HTML, and browser logging UI uses `textContent` for dynamic values.

- **PASS — Failed-attempt rate limiting and lockouts are implemented.**  
  Login, identity OTP, authenticator OTP, and recovery-code verification all count failures and apply a five-minute lock after five failed attempts.

- **FAIL — OTP shared secret, identity OTP, authenticator OTP, and recovery codes are not generated using a cryptographically secure RNG.**  
  `TEST_IDENTITY_OTP`, `TEST_SETUP_SECRET`, `TEST_AUTHENTICATOR_CODE`, and `TEST_RECOVERY_CODES` are fixed source constants. This conflicts with the requirement to generate OTP secrets/codes and recovery codes with cryptographically secure randomness and to provide OTPs with sufficient entropy.

- **FAIL — Recovery-code regeneration does not actually invalidate previously issued code values.**  
  `/api/recovery/generate` always hashes and returns the same `TEST_RECOVERY_CODES`. After regeneration, an old code such as `ALFA-BETA-GAMA` remains in the newly generated hash set and continues to work. This contradicts the UI statement that replacement “will permanently invalidate every current backup code.”

- **PASS — OTP secret and recovery codes are not stored in browser storage or non-HttpOnly cookies.**  
  The client uses in-memory JavaScript variables only. There is no `localStorage`, `sessionStorage`, or client-readable cookie usage for these values.

- **PASS — OTP secret and recovery codes have at-rest protection mechanisms.**  
  The authenticator secret is AES-GCM encrypted in the server-side account structure, and recovery codes are represented as peppered SHA-256 hashes. This is structurally appropriate, although the underlying values are static and therefore fail the secure-generation requirement.

- **PASS — Internal navigation works without external links.**  
  The SPA routes through render functions and button handlers. Help, logout, setup, verification, recovery, and completion transitions are implemented.

- **PASS — No obvious TypeScript or browser JavaScript syntax error prevents startup.**  
  The Bun server and embedded client script are structurally valid. The QR generator is self-contained and does not require network access.

## FAILING_ITEMS

- **Hard-coded security material:**  
  The identity code, authenticator verification code, OTP setup secret, and recovery codes are static constants:
  - `TEST_IDENTITY_OTP = "123456"`
  - `TEST_SETUP_SECRET = "JBSWY3DPEHPK3PXP"`
  - `TEST_AUTHENTICATOR_CODE = "654321"`
  - `TEST_RECOVERY_CODES = [...]`

  These values are predictable to anyone with access to the source and do not satisfy cryptographically secure generation or sufficient entropy requirements.

- **Recovery-code regeneration reissues the same codes:**  
  The regeneration endpoint replaces hashes, but hashes the same fixed list each time. Therefore, a recovery code from a prior set remains valid after “replacement,” defeating the stated invalidation behavior.

- **The fixed recovery-code list weakens the one-time recovery-code security model:**  
  Although each hash is deleted after use, every account and every newly generated set begins with the same known recovery-code values. A fresh recovery-code set is therefore predictable rather than securely generated.

## NEW_TASKS

1. Replace fixed OTP setup secrets, identity/authenticator verification codes, and recovery-code values with values generated using `crypto.getRandomValues`; keep the generated mock values in server memory only and return/log them only in the active browser testing flow.

2. Generate a newly random recovery-code set on every `/api/recovery/generate` request, hash only that newly generated set, and ensure no code from the prior set can validate after regeneration.

3. Update the deterministic-test mechanism so verification remains testable without embedding fixed security values in source code; for example, generate secure values per challenge and return them exclusively in the authenticated browser testing response where the browser logs them.

## DECISION

**FAIL**