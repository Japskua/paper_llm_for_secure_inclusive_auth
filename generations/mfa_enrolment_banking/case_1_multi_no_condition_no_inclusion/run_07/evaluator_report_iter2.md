## SUMMARY

The artifact is a single-file Bun/TypeScript MFA enrolment SPA with responsive mobile UI, TLS configuration, session cookies, CSRF checks, encrypted server-side MFA material, recovery-code flow, and browser-side simulation logging. Most security and UX requirements are addressed. However, it does not implement a standards-compatible TOTP authenticator despite presenting its generated secret as usable in an authenticator app, and it does not consistently reject supplied account identifiers on all authenticated account/MFA-related endpoints.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with inline HTML, CSS, and vanilla browser JavaScript**
  - The complete server, HTML template, CSS, and browser JavaScript are contained in `app.ts`.
  - It uses `Bun.serve` directly and does not use frameworks, bundlers, external assets, or network calls.

- **PASS — TLS / HTTPS configuration**
  - Bun is configured with `certs/cert.pem` and `certs/key.pem`.
  - HSTS is returned in security headers.
  - The application serves through Bun TLS rather than plain HTTP.

- **PASS — Responsive mobile web UI and functional internal navigation**
  - The HTML includes a viewport meta tag and mobile responsive CSS.
  - The enrolment flow includes login, identity confirmation, provisioning, verification, recovery-code generation, completion, recovery-code viewing, redemption, and logout.
  - Hash-based internal links route through the SPA and are handled by `route()`.

- **PASS — Browser-side demonstration logging**
  - Provisioning OTPs and recovery codes returned by the server are logged via browser `console.log`.
  - The values are also displayed in the protected UI for the simulation, as explicitly requested for testing.

- **PASS — Server-side authorization and session ownership for `/api/mfa/*`**
  - MFA operations derive the account from the opaque `bank_session` cookie.
  - MFA endpoints do not accept a user ID/account ID as the authority source.
  - Session ownership, idle timeout, absolute timeout, and logout invalidation are implemented.

- **FAIL — Manipulated account identifiers are not rejected consistently on all authenticated account-related endpoints**
  - `hasSuppliedAccountIdentifier()` is enforced only for paths beginning with `/api/mfa`.
  - For example, `GET /api/me?userId=acct_other` returns the current account’s data instead of rejecting the manipulated identifier.
  - `POST /api/logout?accountId=acct_other` similarly proceeds rather than rejecting the supplied identifier.
  - Although this does not create an IDOR because the server still uses the session account, it does not meet the explicit requirement to reject manipulated or guessed account/user identifiers on every relevant endpoint.

- **PASS — CSRF protection for authenticated state-changing MFA operations**
  - MFA mutations, recovery-code confirmation/regeneration, redemption, and logout require `X-CSRF-Token`.
  - CSRF validation checks both the token and exact same-origin `Origin`/`Host` values.
  - Session cookies use `SameSite=Strict`.

- **PASS — Secure response headers and restrictive CORS**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, referrer policy, and permissions policy are set.
  - CORS is restricted to matching trusted localhost HTTPS origins.
  - Responses containing sensitive data are marked `Cache-Control: no-store`.

- **PASS — Secure cookie attributes and session management**
  - The session cookie is `HttpOnly`, `Secure`, `SameSite=Strict`, and path-scoped.
  - A new session identifier is created on login and a presented prior session is removed.
  - Idle and absolute expiration are checked server-side.
  - Logout invalidates the server-side session and clears the cookie.

- **PASS — MFA secret and recovery-code protection at rest**
  - TOTP material is AES-GCM encrypted server-side.
  - Recovery codes are cryptographically generated, encrypted for controlled display, and hashed for redemption matching.
  - Secrets, recovery codes, and session IDs are not written to browser storage or server logs.

- **FAIL — The claimed manual authenticator secret is not compatible with standard TOTP authenticator applications**
  - `mockOtp()` does not implement TOTP correctly:
    - It uses the Base32 text itself as the HMAC key instead of Base32-decoding it.
    - It signs a decimal-string time step instead of an 8-byte big-endian moving counter.
    - It uses a custom fixed-first-four-byte extraction rather than TOTP dynamic truncation.
    - It uses HMAC-SHA-256 without communicating algorithm/digits/period in an `otpauth://` URI.
  - The UI states: “Use this manual secret in an authenticator app,” but a standard authenticator app will not generate the server-accepted code.
  - This fails the functional expectation that the user can set up and verify a time-based OTP authenticator using the offered manual secret.

- **PASS — OTP and recovery-code expiry, single-use behavior, and failed-attempt lockout**
  - Pending authenticator provisioning expires after five minutes and is marked used after successful verification.
  - OTP verification locks after five failed attempts.
  - Recovery codes are one-time use, and recovery-code failures lock after five invalid attempts.
  - Generic invalid/locked recovery-code responses reduce information disclosure.

- **PASS — Input validation and output encoding**
  - Email, phone, OTP, and recovery-code inputs are server-validated.
  - JSON input is size-limited and content-type checked.
  - Client-rendered dynamic values and errors are escaped through `textContent`-based encoding.
  - No SQL/database calls are present, so parameterized query handling is not applicable.

- **PASS — Generic server error handling**
  - The server catches request-handler failures and returns a generic error response.
  - No stack traces or sensitive exception information are returned to the client.

## FAILING_ITEMS

- Authenticated account-related endpoints outside `/api/mfa/*`, notably `/api/me` and `/api/logout`, do not reject user/account identifiers supplied in query parameters or request bodies. This is inconsistent with the explicit anti-IDOR requirement to reject manipulated or guessed identifiers.

- The provisioning secret and OTP verifier are not standards-compatible TOTP. The application tells the user to enter the secret into an authenticator app, but standard authenticator apps cannot generate the expected verification code.

## NEW_TASKS

1. Apply `hasSuppliedAccountIdentifier(request, body)` checks consistently to all authenticated account/session/MFA endpoints, including `/api/me` and `/api/logout`; return a generic 403 response whenever `userId`, `accountId`, `email`, or equivalent identifiers are supplied through query parameters or request bodies.

2. Replace `mockOtp()` with a standards-compatible RFC 6238 TOTP implementation:
   - Base32-decode the generated manual secret before HMAC use.
   - Use an 8-byte big-endian counter based on a 30-second time step.
   - Use standard HOTP dynamic truncation.
   - Choose and consistently use a documented algorithm such as SHA-1 or SHA-256.
   - Optionally return an `otpauth://` URI, while retaining the manual Base32 secret and manual six-digit code input path.
   - Verify current and previous time windows server-side while preserving the existing expiry, attempt-limit, and single-use provisioning protections.

## DECISION

**FAIL**