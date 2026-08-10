## SUMMARY

The artifact is a well-structured single-file Bun HTTPS SPA with responsive mobile UI, server-side sessions, CSRF checks, secure headers, encrypted TOTP seed storage, and working identity/TOTP enrolment flows. However, it does not fully meet the stated simulation, recovery-code, and authentication-security requirements. In particular, default academic mode does not consistently log required mock values in the browser, recovery codes cannot be verified or consumed, and sign-in attempts are not rate-limited or locked out.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no build tools or external assets.**  
  The HTML, CSS, browser JavaScript, API logic, and Bun server are all contained in `app.ts`. No framework, bundler, compiler, or external network asset is used.

- **PASS — HTTPS/TLS server configuration.**  
  `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`, as required.

- **PASS — Mobile-responsive, dyslexia-conscious UI.**  
  The UI uses a constrained mobile layout, generous spacing, large controls, readable font sizing, adequate letter spacing, concise wording, icons, visible progress, short examples, and no moving/auto-updating content.

- **PASS — Clear MFA enrolment flow.**  
  The flow supports sign-in, identity-code delivery and verification, authenticator provisioning by QR code or setup key, authenticator-code verification, recovery-code generation, and completion.

- **PASS — Manual authenticator setup is supported.**  
  The provisioning secret and provisioning URI are visibly available and copyable. The QR code is generated locally without an external dependency.

- **PASS — Identity-code verification is functional.**  
  Identity codes are time-bound, single-use, hashed before storage, validated as six digits, and protected by failed-attempt lockout logic.

- **PASS — TOTP verification is functional.**  
  TOTP uses HMAC-SHA-1 with 30-second counters and six-digit output. It accepts a narrow counter window, blocks replay of accepted counters, and locks after repeated failures.

- **FAIL — Default academic simulation does not consistently expose required mock values through browser `console.log`.**  
  The requirements state that mocks, including OTPs and recovery codes for testing, must be returned to the UI and shown in the browser console. In default academic mode (`MFA_PRODUCTION_MODE` unset), identity codes are logged, but recovery codes are only logged when `MFA_DEMO_MODE=true`. Authenticator test codes are likewise only returned/logged in `TEST_MODE`, not in default academic mode.

- **FAIL — Authenticator provisioning is not deterministic in the default academic mode.**  
  `ACADEMIC_MODE` is the default, but the TOTP secret is random unless `MFA_DEMO_MODE=true`. The requirements specify simulated authenticator provisioning and deterministic mock values for testing. A separate opt-in environment mode should not be necessary for the required academic testing behavior.

- **FAIL — Recovery codes are generated and hashed but cannot be verified, redeemed, or made single-use.**  
  There is no endpoint or workflow to submit a recovery code. Therefore, the system cannot demonstrate that recovery codes work, are single-use, or are invalidated after use. This leaves the recovery-code portion incomplete.

- **FAIL — Sign-in authentication has no rate limiting or account lockout.**  
  `/api/signin` permits unlimited failed password submissions. The requirements require rate limiting and lockout for repeated authentication/verification failures. OTP-related endpoints have lockout controls, but password sign-in does not.

- **PASS — Server-side authorization avoids client-supplied account identifiers.**  
  MFA endpoints derive the account from the authenticated session rather than accepting user IDs from the client. Stage checks also prevent skipping enrolment steps.

- **PASS — CSRF protection exists on state-changing authenticated MFA endpoints.**  
  State-changing MFA requests require a session-bound `X-CSRF-Token` and enforce an allowed origin. Session cookies use `SameSite=Strict`.

- **PASS — Secure cookie attributes are present.**  
  The session cookie is `HttpOnly`, `Secure`, and `SameSite=Strict`. The CSRF cookie is intentionally readable by browser JavaScript for double-submit protection and is also `Secure` and `SameSite=Strict`.

- **PASS — Security response headers are configured.**  
  Responses include CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, restrictive referrer policy, and a restrictive permissions policy.

- **PASS — No browser storage of secrets or session tokens.**  
  The implementation does not use `localStorage` or `sessionStorage`. The session token is held in an `HttpOnly` cookie.

- **PASS — Sensitive server values are not logged by the server.**  
  There are no server-side logs of OTP seeds, OTP values, backup codes, or sessions. Browser-console logging is used for simulation output.

- **PASS — Input validation and safe DOM rendering are generally implemented.**  
  Email, password, and OTP values are validated server-side. Client rendering uses `textContent` and DOM APIs rather than unsafe HTML interpolation, reducing XSS exposure.

- **PASS — Sessions have idle and absolute expiration and logout invalidation.**  
  Session validity is checked on requests, includes idle and absolute timeouts, a fresh session ID is created on sign-in, and logout removes the server-side session.

## FAILING_ITEMS

- In default academic mode, recovery codes are displayed in the UI but are not written to the browser console because logging is guarded by `if (testMode)`.
- In default academic mode, the authenticator seed is random and the current test TOTP is not returned/logged. Deterministic testing behavior only occurs when `MFA_DEMO_MODE=true`.
- No recovery-code verification endpoint or UI exists. Generated recovery codes cannot be submitted, checked against stored hashes, consumed once, or demonstrated as working.
- `/api/signin` has no failed-attempt counter, rate limit, or temporary lockout. Unlimited password guessing is possible.
- Because recovery codes cannot be redeemed, the requirement for verification codes to be single-use and demonstrably functional is not satisfied for recovery codes.

## NEW_TASKS

1. Make academic mode provide deterministic identity, authenticator, and recovery-code mock values by default, or replace the separate `MFA_DEMO_MODE` dependency with a clearly defined academic-test mode enabled by default.

2. Log all required simulated test values in the **browser console** in academic mode, including the authenticator setup/test value and generated recovery codes, while ensuring server logs never contain them.

3. Add a recovery-code verification API endpoint that:
   - requires an authenticated owner session and CSRF token,
   - validates recovery-code format,
   - compares submitted codes against stored hashes,
   - removes or marks a matching code as used,
   - returns generic invalid responses,
   - rate-limits and locks repeated failures.

4. Add a small recovery-code verification/recovery simulation UI screen or controlled test action so generated recovery codes can be manually entered and their one-time behavior can be demonstrated.

5. Add failed sign-in attempt tracking with a rate limit and temporary lockout for repeated incorrect credentials, using generic non-enumerating error responses.

## DECISION

FAIL