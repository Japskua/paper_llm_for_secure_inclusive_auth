## SUMMARY

The artifact is a well-structured single-file Bun application with a responsive mobile UI, TLS configuration, CSP nonces, secure cookie attributes, CSRF checks, encrypted MFA-secret storage, hashed recovery codes, and browser-side mock logging. However, it does not meet the requirements overall: the CORS allow-list rejects normal same-origin POST requests on the configured `https://localhost:3000` server, sign-in authenticates any syntactically valid email/phone as Marcus, and the OTP implementation includes a permanent fixed bypass rather than a time-based authenticator verification. These are functional and security-critical failures.

## FUNCTIONAL_CHECK

- **FAIL — Single-file Bun server, HTML, CSS, and vanilla browser JavaScript**
  - The entire artifact is contained in `app.ts`, uses `Bun.serve`, and embeds the HTML/CSS/client JavaScript. No framework, bundler, or external assets are used.
  - However, this criterion cannot be fully accepted because core browser POST interactions are broken by the CORS configuration.

- **PASS — TLS/HTTPS server configuration**
  - `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`.
  - HSTS is sent through `Strict-Transport-Security`.

- **PASS — Responsive mobile UI and semantic structure**
  - The UI uses responsive sizing, mobile viewport metadata, accessible labels, forms, buttons, focus states, and layout adjustments for narrow widths.
  - The enrolment, OTP confirmation, recovery-code display, regeneration, recovery-code verification, and logout screens are present.

- **FAIL — Core enrolment flow works in the browser**
  - `applyCors()` rejects every request containing an `Origin` not exactly equal to one of:
    - `https://localhost`
    - `https://127.0.0.1`
    - `https://[::1]`
  - The Bun server defaults to port `3000`, so same-origin browser POSTs typically have an Origin such as `https://localhost:3000`, which is not in `TRUSTED_ORIGINS`.
  - Consequently, `/api/auth/signin` and all subsequent POST endpoints can return `403`, preventing normal enrolment, OTP confirmation, MFA activation, recovery-code regeneration, and logout.

- **PASS — Manual authenticator setup is available**
  - The provisioning screen displays a manually enterable setup secret.
  - The secret and simulated OTP are also sent to browser `console.log`, as required for the academic mock flow.

- **FAIL — Authentication identifies and authorizes only the account owner**
  - `/api/auth/signin` accepts any email and phone that merely match the regular expressions.
  - It then always retrieves and authenticates `users.get("acct_marcus")`.
  - For example, any attacker submitting `attacker@example.test` and a syntactically valid phone number receives a valid authenticated Marcus session.
  - This violates authenticated-account ownership and enables unauthorized access to Marcus’s MFA settings.

- **PASS — IDOR protections on authenticated MFA endpoints**
  - Authenticated routes derive the account exclusively from the opaque session token.
  - URL and JSON-body account identifiers such as `id`, `uid`, `userId`, and `accountId` are rejected.
  - No endpoint accepts a user/account identifier to select another user’s MFA record.

- **PASS — CSRF protection for authenticated state-changing MFA actions**
  - Authenticated POST endpoints require `X-CSRF-Token` and compare it with the session CSRF token using `secureEqual`.
  - The session cookie uses `SameSite=Strict`.
  - MFA enablement, verification, recovery-code regeneration, recovery-code use, and logout are protected.

- **FAIL — CORS is safely restricted without breaking trusted same-origin traffic**
  - The intent to restrict CORS is correct, but the actual trusted-origin list omits the server’s port.
  - It treats ordinary same-origin requests as disallowed cross-origin requests when an `Origin` header is present.
  - This is both a functional defect and an incorrect origin-validation implementation.

- **PASS — Security response headers and error handling**
  - CSP includes nonce-based `script-src` and `style-src`, `frame-ancestors 'none'`, `form-action 'self'`, and restrictive default sources.
  - HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`, and `Cache-Control: no-store` are present.
  - Errors are generic and do not expose stack traces.

- **PASS — Secure session-cookie configuration and session lifecycle**
  - Session cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - Sessions are regenerated at sign-in, have idle and absolute expiration checks, and are removed on logout.
  - Session identity is stored server-side rather than in browser storage.

- **PASS — Sensitive storage protections**
  - Provisioned authenticator secrets are AES-GCM encrypted before being placed in the user record.
  - Recovery codes are generated with `crypto.getRandomValues`, hashed with a pepper, and plaintext codes are only returned in the one-time mock response.
  - No secret/token is placed in URL query parameters, localStorage, sessionStorage, or a browser-readable cookie.
  - Browser console disclosure is present specifically because the requirements explicitly require mock values to be returned to the UI and logged in the browser.

- **PASS — Server-side validation and output-encoding approach**
  - Email, phone, OTP, and recovery-code inputs are validated server-side.
  - Browser dynamic values are inserted using `textContent` rather than HTML interpolation.
  - Redirects are not implemented, so no open redirect is present.

- **FAIL — OTP verification is time-bound and authenticator-based**
  - The code accepts a global hard-coded OTP, `"123456"`, through:
    ```ts
    const isAcademicTestCode = body.otp === "123456";
    ```
  - This code is explicitly non-expiring and is accepted regardless of the challenge expiration time.
  - The verification code is not derived from the provisioned shared secret and time window; it is a separately generated random challenge. Therefore, the implementation is not a time-based authenticator/TOTP verification flow.
  - The fixed bypass contradicts the requirement that OTPs be time-bound.

- **FAIL — Failed OTP verification is robustly rate-limited/locked out**
  - A challenge is locked after five failed attempts, but `/api/mfa/provision` can immediately create a new verification object with `failures: 0` and `locked: false`.
  - An attacker with a session can repeatedly request a new provisioning challenge to reset the OTP failure counter.
  - The lockout is therefore not durable at the account/MFA-enrolment level.

- **PASS — Recovery codes are single-use and lock after repeated failures**
  - A valid recovery code is removed immediately after verification.
  - Invalid recovery-code attempts increment a server-side counter and lock after five failures.
  - Recovery-code comparisons use a constant-time-style comparison helper.

## FAILING_ITEMS

- Same-origin browser POST requests to the default server URL, such as `https://localhost:3000`, are rejected because `TRUSTED_ORIGINS` does not include the port. This breaks sign-in and the MFA flow.
- Sign-in does not authenticate Marcus’s actual registered identity. Any syntactically valid email and phone receive a session for `acct_marcus`.
- The OTP mechanism is not a time-based authenticator verification based on the provisioned secret.
- The permanent `"123456"` OTP bypass is non-expiring and violates the requirement that verification codes be time-bound.
- OTP lockout can be bypassed by calling `/api/mfa/provision` again, which resets `failures` and `locked`.

## NEW_TASKS

1. Update origin handling so same-origin requests are always allowed and trusted cross-origin requests include the actual configured HTTPS origin and port, such as `https://localhost:3000`; retain restrictive CORS behavior for untrusted origins.

2. Replace the unconditional Marcus sign-in behavior with deterministic mock credential verification that only authenticates the configured Marcus identity, while continuing to return generic failures to avoid account enumeration.

3. Replace the random server challenge and permanent `"123456"` bypass with a deterministic mock TOTP-style verification derived from the provisioned secret and a bounded time step; remove acceptance of any non-expiring universal OTP.

4. Add an account-level MFA-verification failure counter and lockout window that cannot be reset by requesting a new provisioning secret/challenge. Only a defined trusted recovery/reset process should clear that lockout.

## DECISION

FAIL