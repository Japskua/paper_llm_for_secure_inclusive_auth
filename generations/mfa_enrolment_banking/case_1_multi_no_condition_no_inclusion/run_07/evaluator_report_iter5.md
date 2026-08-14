## SUMMARY

The artifact is structurally close to the requested single-file Bun SPA and includes substantial security-oriented logic (TLS, CSP, session cookies, CSRF checks, authorization derived from session state, encrypted MFA material, rate limiting, and a mobile UI). However, it contains a TypeScript syntax error in `phoneOK` that prevents `app.ts` from parsing or starting under Bun. Therefore, none of the UI, API, security controls, or enrolment flow can execute.

## FUNCTIONAL_CHECK

- **Single-file Bun server containing HTML, CSS, and vanilla browser JavaScript: FAIL**
  - The implementation is contained in one `app.ts` and does not use frameworks, build tools, or external assets.
  - However, the source has an unterminated string literal in `phoneOK`, so Bun cannot execute the single file.

- **Bun serves the application with TLS certificates from `certs/cert.pem` and `certs/key.pem`: FAIL**
  - TLS configuration is present and correctly references the required certificate paths.
  - The server cannot start because of the syntax error.

- **Responsive, legible mobile SPA UI: FAIL**
  - The HTML/CSS includes a responsive single-column layout, mobile viewport meta tag, and a narrow-screen media query.
  - The UI cannot render because the application does not compile.

- **Full MFA enrolment flow works (sign-in, identity confirmation, manual authenticator setup, OTP verification, recovery-code generation/storage, completion): FAIL**
  - The intended flow and hash-based routing are implemented.
  - The syntax error prevents all client and server functionality from running.

- **Authenticator secret/code can be submitted or used manually: FAIL**
  - The UI displays a manual Base32 secret and a current test OTP, and the verification page accepts a six-digit OTP.
  - This functionality is unreachable until the source syntax error is corrected.

- **Browser-console-only simulation output for OTPs and recovery codes: FAIL**
  - The client-side `log()` function uses `console.log`, and test OTP/recovery code values are displayed in the browser UI/log panel as required for testing.
  - The browser JavaScript cannot be served due to the server-side parse failure.

- **Server-side authorization and IDOR prevention on MFA endpoints: FAIL**
  - The intended implementation derives account ownership only from the authenticated session and rejects supplied identifier-like request parameters.
  - It cannot be evaluated at runtime because the app does not start.

- **CSRF protection for state-changing MFA operations: FAIL**
  - The intended implementation requires an origin check plus per-session CSRF token for authenticated POST actions, and uses `SameSite=Strict` cookies.
  - It is non-functional until the syntax error is fixed.

- **Secure headers, restricted CORS, and clickjacking protection: FAIL**
  - The code intends to send CSP with nonces, HSTS, `X-Content-Type-Options`, `X-Frame-Options`, referrer policy, permissions policy, and restricted localhost CORS handling.
  - No responses can be generated because the server cannot parse.

- **Secure session handling: FAIL**
  - The intended design uses `HttpOnly`, `Secure`, and `SameSite=Strict` cookies; rotates the session at login; applies idle and absolute expiry; and invalidates the session at logout.
  - This cannot execute because of the syntax error.

- **OTP/recovery-code security and failed-attempt lockouts: FAIL**
  - The intended implementation generates cryptographically random secrets/codes, encrypts the TOTP secret and recovery-code records, uses TOTP verification, marks pending enrolment verification as used, and locks after repeated failures.
  - These protections are unreachable because the server cannot start.

- **Input validation and generic error responses: FAIL**
  - Input validation is intended for email, phone, OTP, recovery codes, JSON content type, and body size, with generic failure messages.
  - The `phoneOK` validator itself is malformed and causes the parse failure.

## FAILING_ITEMS

- `app.ts` has a fatal syntax error in the `phoneOK` declaration:
  ```ts
  const phoneOK = (v: unknown): v is string => typeof v === "string && /^\\+[1-9]\\d{7,14}$/.test(v);
  ```
  - The string beginning with `"string` is never closed.
  - Bun will fail to parse the file with an unterminated string literal error.
  - As a result, the HTTPS server never starts and no API endpoint or browser UI is available.

## NEW_TASKS

1. Correct the `phoneOK` validator so that it performs a type check and phone-regex validation with valid TypeScript syntax:
   ```ts
   const phoneOK = (v: unknown): v is string =>
     typeof v === "string" && /^\+[1-9]\d{7,14}$/.test(v);
   ```

## DECISION

**FAIL**