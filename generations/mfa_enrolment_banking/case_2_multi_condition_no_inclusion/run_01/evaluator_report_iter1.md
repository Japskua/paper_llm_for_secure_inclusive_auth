## SUMMARY

The artifact is a single-file Bun HTTPS SPA with a strong mobile UI, working mock enrolment flow, secure cookie attributes, CSRF checks on authenticated MFA mutations, security headers, encrypted TOTP-secret storage, hashed recovery codes, and generic error handling. However, it does not fully meet the security requirements: account ownership is not actually verified, identity-verification lockout can be bypassed, and the OTP implementation uses predictable fixed values rather than cryptographically strong per-verification codes or real TOTP validation.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun implementation and HTTPS server**
  - `app.ts` contains the Bun server, HTML, CSS, and browser JavaScript. It uses Bun directly without bundlers, frameworks, external assets, or external network calls.
  - The server is configured with the required `certs/cert.pem` and `certs/key.pem` TLS files.

- **PASS — Mobile responsive and accessible-enough SPA UI**
  - The interface uses semantic elements (`main`, `header`, `section`, `form`, `label`, `button`) and responsive CSS suitable for narrow mobile viewports.
  - Inputs have labels, mobile input modes, focus styling, meaningful headings, and live regions for status messages.

- **PASS — MFA enrolment and recovery-code UX is functionally wired**
  - Sign-in, identity verification, enrolment, setup confirmation, recovery-code display, recovery-code use, regeneration, navigation, and logout are all wired to functioning API endpoints.
  - The manual authenticator setup secret is displayed, and the user can manually enter a six-digit setup code.
  - Recovery codes are shown in the UI and logged in the browser console as required for mock testing.

- **FAIL — Server-side account ownership enforcement / IDOR resistance**
  - `/api/signin` creates an account identity solely from any submitted valid email address:
    ```ts
    const accountId = await sha256Text(body.email.trim().toLowerCase());
    ```
  - The submitted phone number is validated only syntactically and is not verified against an account. Any caller can submit another user’s email with an arbitrary valid phone number, receive the globally fixed identity code, and obtain a session associated with that email-derived account ID.
  - Therefore, the application does not establish that the authenticated session belongs to the real account owner before allowing MFA changes.

- **PASS — MFA endpoints require an authenticated session and do not accept user IDs**
  - All `/api/*` routes after identity verification require `authenticated(request)`.
  - MFA records are selected from `session.accountId`, not a client-supplied account ID, which avoids direct parameter-based IDOR.
  - However, this does not compensate for the account-ownership failure in sign-in.

- **PASS — CSRF protections for authenticated MFA mutations**
  - MFA enrolment, confirmation, recovery-code use, recovery-code regeneration, and logout require a per-session `X-CSRF-Token`.
  - Cookies use `SameSite=Strict`, providing an additional CSRF control.

- **PASS — Security headers and CORS restriction**
  - Responses include CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, restrictive referrer policy, permissions policy, and no-store cache control.
  - CORS headers are issued only for configured localhost TLS origins.

- **PASS — Secure session-cookie configuration and session lifecycle**
  - Session and pre-auth cookies use `HttpOnly`, `Secure`, `SameSite=Strict`, and `Path=/`.
  - A new session ID is generated after identity verification, mitigating session fixation.
  - Server-side idle and absolute session expiry are implemented, and logout invalidates the server-side session and expires the cookie.

- **FAIL — OTPs are not cryptographically strong, unique, or truly single-use across authentication attempts**
  - Identity verification always accepts the constant value `"135790"`.
  - Authenticator setup always accepts the constant value `"654321"`.
  - These values are predictable and do not have sufficient entropy.
  - The identity code is only “single-use” for one specific pre-auth token. A caller can start a new sign-in request and reuse the same static code indefinitely.
  - This violates the requirement that verification codes/OTPs be generated with sufficient entropy, time-bound, and single-use.

- **FAIL — Identity-verification rate limiting and lockout are bypassable**
  - Failed identity-verification attempts are stored only in the individual `PreAuth` object.
  - Calling `/api/signin` again creates a new `PreAuth` record with fresh attempts:
    ```ts
    attempts: 0,
    lockedUntil: 0,
    ```
  - An attacker can avoid the five-failure lockout by repeatedly requesting new pre-auth sessions.
  - Lockout must be enforced at least per account and ideally also per source/session, rather than being reset by a new sign-in request.

- **FAIL — The displayed authenticator secret is not actually used for time-based OTP verification**
  - A cryptographically generated secret is displayed and encrypted at rest, but the server never decrypts or uses it to calculate/validate a TOTP code.
  - `/api/mfa/confirm` validates only the fixed `record.setupOtp` value:
    ```ts
    body.otp !== record.setupOtp
    ```
  - As a result, an authenticator app configured with the displayed secret cannot produce a code that the server will verify. This is a mock fixed-code confirmation flow, not functional time-based OTP authenticator provisioning.

- **PASS — Recovery-code generation, protected storage, and single use**
  - Recovery codes are generated with `crypto.getRandomValues`.
  - Codes are HMAC-protected with a server-only pepper and stored as hashes rather than plaintext.
  - A successful recovery-code use marks that code as consumed.
  - Regeneration replaces prior recovery-code hashes.

- **PASS — Input validation and output handling**
  - Server-side validation is present for email, phone, OTP, and recovery-code formats.
  - No database or SQL query layer exists, so prepared-query requirements are not applicable to this implementation.
  - Client rendering uses `textContent` and DOM node creation for dynamic content, reducing reflected and DOM XSS exposure.

- **PASS — Generic error behavior and absence of sensitive server logging**
  - Exceptions are caught and returned as generic error bodies without stack traces.
  - The server does not log OTPs, TOTP secrets, recovery codes, or session tokens.
  - Note: the browser intentionally logs mock secrets/codes because the deliverable explicitly requires this. This conflicts with the literal wording that sensitive values must never appear in “logs,” but it satisfies the explicit browser-console mock requirement.

## FAILING_ITEMS

- The application does not verify that a sign-in email and phone number belong to a real registered account. Any valid email can be converted into an MFA account identifier.
- The fixed identity code (`135790`) and setup code (`654321`) are predictable and reusable across newly created authentication/enrolment attempts.
- Identity-verification lockout is tracked only in a disposable pre-auth record, so a new `/api/signin` request resets failed-attempt counters and bypasses lockout.
- The authenticator secret shown to the user is never used to validate a time-based authenticator code. The implementation does not perform TOTP verification.
- The literal security requirement prohibiting OTPs, secrets, and recovery codes in logs conflicts with the explicit requirement to show mock values in the browser console and UI. The artifact follows the latter, but this should be explicitly scoped as test-only behavior.

## NEW_TASKS

1. Add a server-side mock account registry that maps a registered email address to its registered phone number and stable internal account ID; reject non-matching sign-in details with the same generic response and timing behavior used for valid details.

2. Replace the globally fixed identity code with a cryptographically random six-digit verification code stored server-side with an expiry, used flag, and account/session association; return it only as the required browser-side mock delivery value.

3. Track identity-verification failures and lockout state per account ID independently of the pre-auth token, so requesting a new pre-auth cookie cannot reset failed-attempt counters or bypass lockout.

4. Implement actual TOTP validation using the generated provisioning secret: decrypt the stored AES-GCM secret server-side, calculate accepted current/adjacent time-step codes, and verify the user-entered authenticator code against those values.

5. Remove the fixed setup OTP (`"654321"`) and use either real TOTP validation or a securely generated, per-enrolment mock OTP that is account-bound, time-bound, and marked consumed after successful use.

6. Document and isolate browser-console disclosure of mock OTPs, provisioning secrets, and recovery codes as test-only behavior, ensuring production mode does not render or log these values outside the intended enrolment/recovery display.

## DECISION

FAIL