## SUMMARY

The artifact is a well-structured single-file Bun HTTPS SPA with strong coverage of session ownership, CSRF, security headers, input validation, rate limiting, responsive accessibility-oriented UI, and recovery-code handling. However, it cannot be accepted because the TOTP implementation can generate negative OTP values due to signed JavaScript bitwise arithmetic, making authenticator verification fail for a substantial portion of secrets. The custom QR generator is also not standards-compliant for the stated QR version and may not scan reliably. These are core functional defects in MFA enrolment.

## FUNCTIONAL_CHECK

- **Single-file Bun server with inline HTML, CSS, and vanilla JavaScript — PASS**
  - The complete application is contained in `app.ts`.
  - It uses `Bun.serve`, serves generated HTML directly, and uses no framework, bundler, compiler, or external assets.

- **HTTPS/TLS is configured using the required certificate paths — PASS**
  - The server uses:
    ```ts
    tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") }
    ```
  - Requests are additionally rejected unless the URL is HTTPS and the hostname is trusted.

- **Mobile-responsive, legible MFA enrolment UI — PASS**
  - The page includes a mobile viewport meta tag, constrained responsive content width, mobile media queries, adequate spacing, large input controls, clear step indicators, and plain-language instructions.
  - The UI includes examples for email, OTP, and recovery-code input.

- **Dyslexia/inclusivity requirements — PASS**
  - The interface avoids dense text, all-caps instructions, italics, animation, and timers.
  - It provides generous spacing, copy buttons, QR/manual-secret alternatives, short help sections, retry paths, hide/show controls, clear error messages, and browser autofill attributes.
  - The UI makes the current step and primary action prominent.

- **Authenticator provisioning, manual secret option, and QR-code option — FAIL**
  - A manual secret is correctly shown and can be copied.
  - However, the custom QR generator is not compliant with QR Version 10 requirements:
    - A Version 10 QR code must reserve and populate version-information areas.
    - Version 10 alignment pattern positions should be `[6, 28, 50]`, but the implementation uses `[6, 22, 38, 50]`.
    - The generator writes payload bits into areas that must be reserved for version information.
  - As a result, the displayed QR code may not be scannable by authenticator applications.

- **OTP verification works reliably — FAIL**
  - `totpForCounter()` constructs the dynamic-truncation integer with signed JavaScript bitwise operators:
    ```ts
    const binary = ((signature[offset] & 127) << 24) |
      (signature[offset + 1] << 16) |
      (signature[offset + 2] << 8) |
      signature[offset + 3];
    ```
  - JavaScript bitwise results are signed 32-bit integers. When the resulting top bit is set, `binary` becomes negative.
  - `binary % 1_000_000` can therefore be negative, producing values such as `"-12345"` rather than a six-digit code.
  - The API then rejects that value because `validOtp()` only permits `/^\d{6}$/`.
  - This can make a correct authenticator code impossible to verify for many secrets and is a core MFA-flow failure.

- **Mock OTPs and recovery codes are provided to the browser and browser console — PARTIAL / FAIL**
  - Recovery codes are returned to the browser, rendered in the UI, and logged through browser `console.log`.
  - The mock OTP is returned from `/api/provision` and logged in the browser console, but it is not rendered in the UI.
  - The deliverable explicitly requires mock OTPs and recovery codes to be returned to the UI and shown in browser console logs for testing.
  - Additionally, the implementation logs the authenticator seed:
    ```js
    safeConsole("Mock authenticator setup delivered. Secret: "+setupSecret);
    ```
    This conflicts with the security requirement not to expose OTP seeds in logs.

- **Backup recovery codes are securely generated, stored, displayed, copied, regenerated, and single-use — PASS**
  - Codes are generated with `crypto.getRandomValues`.
  - Codes are stored as keyed HMAC-SHA-256 verifiers, rather than plaintext.
  - They are displayed once after creation, can be copied or hidden/revealed, regenerated, and are removed after successful use.
  - Recovery-code verification uses a constant-time comparison and supports lockout after repeated failures.

- **Broken access control / IDOR prevention — PASS**
  - The authenticated account is derived only from the server-side session:
    ```ts
    const account = accounts.get(session.userId);
    ```
  - No user/account identifier is accepted from MFA API request bodies or URLs.
  - MFA provisioning, verification, recovery-code use, regeneration, and logout require a valid session.

- **CSRF protection for state-changing operations — PASS**
  - State-changing requests require both a same-origin HTTPS `Origin` header and a per-session CSRF token.
  - Session cookies use `SameSite=Strict`.
  - Sign-in is protected by strict same-origin validation and does not rely on an existing authenticated session.

- **Secure headers, CORS restriction, clickjacking protection, and generic server failures — PASS**
  - The application sets CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, `Permissions-Policy`, and `Cache-Control: no-store`.
  - CORS is only enabled for the exact same trusted HTTPS origin.
  - Unhandled server errors return a generic message rather than stack traces.

- **Session security — PASS**
  - Session IDs and CSRF tokens are generated using cryptographic randomness.
  - Cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - Sessions have idle and absolute expiry checks.
  - Existing sessions for the account are removed when signing in, mitigating session fixation and concurrent stale sessions.
  - Logout invalidates the session and expires the cookie.

- **Input validation and XSS/injection protections — PASS**
  - The API validates email, password, OTP, and recovery-code formats.
  - No database queries are present, so SQL injection is not applicable to this in-memory mock.
  - Dynamic values inserted into HTML are passed through `esc()` before insertion.
  - No user-controlled redirect URL is accepted.

- **OTP and recovery-code replay/rate-limit requirements — PASS, subject to the TOTP defect**
  - OTP counters are tracked and cannot be reused.
  - OTP and recovery-code verification both lock after five failures for five minutes.
  - OTP verification permits a bounded adjacent TOTP time window.
  - The rate-limiting design is sound, but reliable OTP verification is still blocked by the signed-integer bug.

## FAILING_ITEMS

- **TOTP generation is incorrect due to signed 32-bit bitwise arithmetic.**
  - Valid HOTP/TOTP dynamic truncation output must be treated as an unsigned 31-bit integer.
  - The current implementation can produce negative OTP values and then rejects them as invalid six-digit codes.
  - This makes core MFA verification unreliable.

- **The custom QR-code encoder does not implement a valid Version 10 QR symbol.**
  - It uses incorrect Version 10 alignment-pattern positions.
  - It omits required version-information reservation/encoding for QR versions 7 and above.
  - Authenticator apps may fail to scan the QR code.

- **The mock OTP is not visibly returned in the UI.**
  - It is returned in the network response and logged to the browser console, but it is not rendered on-screen.
  - This does not fully meet the testing deliverable requiring mock OTPs to be returned to the UI and logged in the browser console.

- **The authenticator secret is logged to the browser console.**
  - The explicit mock requirement calls for browser-console output for test values such as OTPs and recovery codes, but it does not require the OTP seed to be logged.
  - Logging the seed conflicts with the requirement not to expose OTP seeds in logs.

## NEW_TASKS

1. **Fix TOTP dynamic truncation to use an unsigned integer.**
   - Replace the signed `binary` expression in `totpForCounter()` with an unsigned calculation, for example:
     ```ts
     const binary = (
       ((signature[offset] & 0x7f) << 24) |
       (signature[offset + 1] << 16) |
       (signature[offset + 2] << 8) |
       signature[offset + 3]
     ) >>> 0;
     ```
   - Confirm that the function always returns exactly six decimal digits and that the displayed mock OTP successfully verifies.

2. **Replace or correct the custom QR encoder.**
   - Implement a standards-compliant QR code encoder for the selected version/error-correction level, including correct alignment locations and version information.
   - Alternatively, implement a smaller valid QR version appropriate to the provisioning URI length, including all required QR structural fields.
   - Verify with at least one standard authenticator app or QR decoder that the rendered `otpauth://` URI scans correctly.

3. **Expose the mock OTP in the testing UI without changing the normal verification mechanics.**
   - Add a clearly labeled mock/testing disclosure on the provisioning or verification screen that renders the server-returned mock OTP.
   - Keep the existing browser `console.log` output.
   - Ensure the displayed mock code updates when a new provisioning secret is requested.

4. **Stop logging the authenticator seed.**
   - Remove:
     ```js
     safeConsole("Mock authenticator setup delivered. Secret: "+setupSecret);
     ```
   - Retain the required browser logging for the mock OTP and recovery codes only.

## DECISION

**FAIL**