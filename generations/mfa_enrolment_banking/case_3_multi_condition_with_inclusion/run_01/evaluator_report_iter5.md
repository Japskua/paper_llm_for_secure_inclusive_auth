## SUMMARY

The artifact is a single-file Bun MFA enrolment application with a functional mobile-oriented flow, server-side sessions, CSRF checks, TLS, secure headers, input validation, encrypted OTP seed storage, hashed recovery codes, and rate limiting. However, it does not fully meet the stated requirements: it lacks a QR-code option, uses a permanent deterministic authenticator code rather than a time-bound OTP, and logs sensitive OTP/recovery values to the browser console despite the security requirement forbidding such logging. There is also an unresolved contradiction between the requested browser-console mock logging and the requirement never to log OTPs or backup codes.

## FUNCTIONAL_CHECK

- **Single `app.ts` Bun application with inline HTML, CSS, and JavaScript; no frameworks/build tools/external assets: PASS**
  - The complete server and client app are contained in one TypeScript file.
  - It uses `Bun.serve`, inline HTML/CSS/JS, no imports, no framework, and no external network requests.

- **Bun serves the application over supplied TLS certificates: PASS**
  - `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`.
  - The server announces an HTTPS localhost URL.

- **Responsive and mobile-legible UI: PASS**
  - The page has an appropriate viewport tag, constrained mobile-first layout, large controls, generous input heights, readable font sizing, spacing, and a small-viewport media query.

- **Plain-language, dyslexia-conscious UI and predictable step flow: PASS**
  - The UI uses short instructions, icons, step numbers, examples for expected inputs, prominent primary actions, help details, clear errors, reveal/hide controls, and no moving or time-pressure UI.
  - Browser autofill attributes are present for email, credentials, and one-time codes.

- **Authenticator provisioning supports manual secret entry and copy-to-clipboard: PASS**
  - The setup screen provides a manually copyable/revealable secret and provisioning URI.
  - It does not require manual transcription of the secret.

- **Authenticator provisioning includes a QR-code option: FAIL**
  - The requirements explicitly call for QR-code options.
  - The setup page explicitly states, “No QR code is needed,” and no QR code is rendered or offered.

- **Identity verification, authenticator verification, recovery-code verification, regeneration, and logout work: PASS**
  - The application implements all relevant endpoints and client transitions.
  - Identity verification leads to provisioning; authenticator verification generates recovery codes; recovery codes are single-use; regeneration replaces existing code hashes; logout invalidates the session.

- **Mocks are deterministic and surfaced to the UI/browser console for testing: PASS, but conflicts with security requirements**
  - Identity and authenticator mock codes are deterministic.
  - Authenticator and recovery-code mock values are returned to the UI and logged in the browser console as requested by the deliverable.
  - This behavior directly conflicts with the separate “never expose ... in logs” security requirement.

- **Server-side authorization and IDOR protection on MFA endpoints: PASS**
  - MFA operations derive the account exclusively from the authenticated server-side session.
  - No user/account identifier is accepted from the client for MFA operations.
  - Guessed or manipulated account identifiers cannot select another account.

- **CSRF protection on state-changing requests: PASS**
  - State-changing requests require both an allowed `Origin` and a session-bound `X-CSRF-Token`.
  - The session cookie is `SameSite=Strict`, providing additional CSRF protection.

- **Secure headers and clickjacking protection: PASS**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, Referrer Policy, and Permissions Policy are configured.

- **Secure session-cookie configuration and session lifecycle: PASS**
  - Cookies use `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - Sessions have idle and absolute expiry, are rotated on sign-in, and are invalidated on logout.

- **CORS restricted to trusted origins: PASS**
  - CORS is only enabled for explicit localhost TLS origins.
  - State-changing routes additionally reject requests whose `Origin` is not trusted.

- **OTP seed and recovery-code storage protection: PASS**
  - OTP seeds are AES-GCM encrypted before being placed in account state.
  - Recovery codes are stored only as SHA-256 hashes with a random server-side pepper.
  - Cryptographically secure random generation is used for secrets, sessions, CSRF tokens, and recovery-code values.

- **No sensitive values in logs, URL query strings, or error output: FAIL**
  - `browserLog("[Mock authenticator test code] " + result.mockCode)` logs the authenticator OTP.
  - `browserLog("[Mock recovery codes] " + result.codes.join(", "))` logs all recovery codes.
  - The provisioning URI contains the shared secret as a `secret=` query parameter. Although it is displayed as a string rather than used as the browser page URL, it is still a URI query containing a sensitive OTP seed.
  - This conflicts with the explicit security requirement prohibiting logging of OTPs and backup codes. It also conflicts with the separate testing requirement asking for browser-console logging; this must be formally reconciled.

- **Validation, output encoding, and redirect safety: PASS**
  - Server-side validation exists for email, credential, six-digit codes, and recovery-code format.
  - Dynamic client-rendered data is escaped through `esc`.
  - There are no redirect parameters or externally controlled redirects.

- **Verification codes are single-use, time-bound, sufficiently protected, and rate-limited: FAIL**
  - Identity codes are single-use and expire after 30 minutes.
  - Recovery codes are single-use and attempts are rate-limited/locked.
  - Authenticator codes are single-use and attempts are rate-limited/locked.
  - However, the authenticator check is created with `Number.MAX_SAFE_INTEGER` as its expiry:
    ```ts
    a.authenticatorCheck = await check(DEMO_AUTHENTICATOR_CODE, Number.MAX_SAFE_INTEGER);
    ```
    This means it effectively never expires, violating the requirement that OTPs be time-bound.
  - The authenticator code is always the static value `654321`, rather than a securely generated verification value. A deterministic mock can still have a generous fixed validity period, but it must expire.

- **Generic production error behavior without verbose stack traces: PASS**
  - Top-level server exceptions return a generic 500 response.
  - Stack traces are not returned to clients.

## FAILING_ITEMS

- The authenticator setup screen does not provide a QR-code option, despite the inclusivity requirement to offer QR-code options alongside copy/manual-entry support.
- The authenticator verification code never expires because its expiry is set to `Number.MAX_SAFE_INTEGER`; this violates the time-bound OTP requirement.
- The application logs authenticator OTPs and recovery codes through `console.log` in the browser.
- The provisioning URI exposes the OTP seed in a `secret=` URI query parameter. This is inherent to a standard `otpauth://` provisioning URI, but it conflicts with the requirement not to expose OTP seeds in URL query strings.
- The requirements themselves conflict: they require OTP/recovery mocks to be shown via browser `console.log`, while also requiring that OTPs and backup codes never be exposed in logs. The implementation follows the mock-delivery instruction but fails the stated security prohibition. This requires an explicit policy decision rather than an implicit exception.

## NEW_TASKS

1. Add a QR-code provisioning option on the authenticator setup screen, generated entirely locally with inline JavaScript and no external assets or network requests; retain the existing manual secret and copy controls.

2. Replace the effectively permanent authenticator verification expiry with a finite, generous validity period, such as 30 minutes, and return a clear message allowing Marcus to re-open/re-request setup details after expiry without penalty.

3. Make the deterministic authenticator mock code time-bound while preserving testability; for example, keep `654321` as the test value but store it with a finite expiry and regenerate its check record when setup is re-requested.

4. Reconcile the contradictory secret-logging requirements. Either:
   - remove browser-console logging of OTPs and recovery codes to satisfy the security requirement, or
   - amend the requirements to explicitly allow browser-only localhost test logging as a narrowly scoped exception, separate from production behavior.

5. Avoid exposing the OTP seed through a displayed provisioning URI query string if strict compliance with the “no secrets in URL query strings” rule is required. Prefer a locally generated QR representation plus the separately revealable/copyable manual secret, or formally document an explicit exception for standard `otpauth://` provisioning URIs.

## DECISION

**FAIL**