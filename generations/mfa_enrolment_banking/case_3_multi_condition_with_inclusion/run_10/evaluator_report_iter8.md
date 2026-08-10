## SUMMARY

The artifact is a single-file Bun HTTPS SPA with substantial security and accessibility intent, including secure headers, CSRF checks, encrypted TOTP-secret storage, hashed recovery codes, lockouts, and mobile-oriented UI. However, it has a critical runtime error in session-cookie parsing that prevents the app from bootstrapping or signing in. A second endpoint has a request-body double-read bug, and the custom QR generator does not reserve format modules before data placement, making the offered QR code unreliable/invalid. The rendered on-page log also exposes sensitive test values unnecessarily.

## FUNCTIONAL_CHECK

- **Single-file Bun server with inline HTML, CSS, and vanilla browser JavaScript — PASS**
  - The entire application is contained in `app.ts`.
  - It uses `Bun.serve`, direct HTML generation, inline CSS, and inline vanilla JavaScript.
  - No frameworks, build tools, bundlers, or external assets are used.

- **Uses TLS certificates from `certs/cert.pem` and `certs/key.pem` — PASS**
  - The server reads these exact files and configures Bun TLS with them.

- **Mobile-responsive, readable, dyslexia-aware enrolment UI — PASS (static implementation)**
  - The UI uses a constrained mobile layout, readable sizing, generous line spacing, plain wording, examples, help text, no animations, and one prominent primary action per screen.
  - Copy, reveal/hide, print/PDF, QR, and manual-secret paths are provided.
  - This cannot function in practice until the session runtime failure is fixed.

- **Application can bootstrap and begin sign-in — FAIL**
  - `current()` contains:
    ```ts
    const id = parseCookies(request).__Host_mfa_session || parseCookies(request).__Host-mfa_session;
    ```
  - The second expression is parsed as subtraction:
    ```ts
    parseCookies(request).__Host - mfa_session
    ```
    where `mfa_session` is an undeclared variable.
  - This throws a `ReferenceError` whenever `current()` executes.
  - `/api/bootstrap` invokes `current()`, returns a generic 500 response, and the SPA cannot initialize a usable sign-in screen.
  - `/api/signin` also invokes `current()` and therefore cannot complete even if the UI were reached.

- **Authenticated ownership enforcement / no IDOR — PASS (design), FAIL (operationally blocked)**
  - Protected MFA routes derive account access from the HttpOnly session’s `userId`; clients do not submit a target user ID.
  - `owner()` checks the session, stage, CSRF token, and retrieves the account only from the server-held session identity.
  - Operational verification is blocked by the `current()` runtime error.

- **CSRF protection for state-changing actions — PASS (design)**
  - State-changing endpoints require `X-CSRF-Token`.
  - The app rotates CSRF values at key stage transitions.
  - Session cookies use `SameSite=Strict`.
  - Sign-in requires a CSRF token from the pre-authentication bootstrap session.

- **Secure session-cookie attributes and secure session lifecycle — PASS (design)**
  - Cookie configuration includes `HttpOnly`, `Secure`, `SameSite=Strict`, and `Path=/`.
  - The `__Host-` cookie naming convention is used correctly in the emitted cookie name: `__Host-mfa_session`.
  - Session rotation occurs on successful sign-in.
  - Idle and absolute expiry are implemented.
  - Logout invalidates the server session and clears the cookie.
  - This is currently unusable because cookie retrieval is broken in `current()`.

- **Security headers and CORS restriction — PASS**
  - CSP uses per-page nonces and includes `frame-ancestors 'none'`.
  - HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`, and `Cache-Control: no-store` are set.
  - CORS is only emitted for the configured localhost TLS origins.

- **No browser persistence of secrets or tokens — PASS**
  - The client does not use `localStorage`, `sessionStorage`, IndexedDB, or non-HttpOnly cookies for secrets or sessions.

- **Cryptographically secure OTP/recovery-code generation and protected storage — PASS**
  - Random values use `crypto.getRandomValues`.
  - TOTP secrets are AES-GCM encrypted before being retained in the account record.
  - Recovery codes are stored as PBKDF2-derived values with individual salts, not plaintext.
  - TOTP and recovery-code verification uses constant-time comparison helpers.

- **OTP expiry, single use, replay prevention, and lockouts — PASS (design)**
  - Identity OTPs expire after 10 minutes, are marked used, and failed attempts lead to lockout.
  - TOTP verification uses a time window and records `mfaLastCounter` to reject replayed counter values.
  - Recovery codes are removed after successful use.
  - OTP and recovery-code paths have failure limits and lockouts.

- **Identity-code request and verification flow — FAIL (operationally blocked)**
  - The implementation is structurally sound, including input validation, throttling, secure random codes, and browser-console test code exposure.
  - It cannot be reached because session lookup crashes.

- **New authenticator provisioning, manual secret entry, and OTP verification — FAIL (operationally blocked)**
  - The app does provide QR and manual setup-key paths, and returns a deterministic/current test TOTP for the browser console in localhost academic mode.
  - It cannot be reached because session lookup crashes.
  - The QR implementation has an additional correctness defect described below.

- **QR option is functional and usable — FAIL**
  - `qrSvg()` writes payload data into modules that should be reserved for QR format information.
  - Format bits are written only after data placement:
    ```js
    // Data placement occurs while format-information positions remain null.
    ...
    // Format modules are overwritten afterwards.
    const fmt="111011111000100";
    ```
  - Overwriting those populated modules shifts/truncates the data stream and produces an invalid or unreliable QR symbol.
  - Because the UI explicitly offers a scannable QR setup option, it must generate standards-compliant QR codes.

- **Existing-MFA challenge accepts authenticator code or recovery code — FAIL**
  - `/api/mfa/existing/verify` reads `request.body` twice:
    ```ts
    const submitted = typeof (await body(request))?.code === "string"
      ? (await body(request))?.code
      : "";
    ```
  - A `Request` body can only be consumed once. For normal string input, the second `await body(request)` throws, the top-level handler catches it, and the endpoint returns a generic 500 error.
  - This prevents existing users from completing the MFA challenge with either an authenticator code or a recovery code.

- **Recovery code view/copy/print/hide/regenerate and one-time use — FAIL (partly operationally blocked)**
  - The intended recovery-code UI supports reveal/hide, copy, print/PDF, acknowledgement, regeneration, and one-time server-side use.
  - The normal flow cannot reach this stage due to the broken session lookup.
  - Additionally, sensitive recovery codes are copied into the persistent on-page “Logs” panel.

- **Mocks are exposed through browser console logging without server logs — PASS with a security UX issue**
  - Identity OTPs, authenticator test OTPs, and recovery codes are logged with browser `console.log`, consistent with the academic-test requirement.
  - The server does not log secrets.
  - However, the app also renders these values into a persistent visible “Logs” panel, which is not necessary for browser-console testing and increases accidental disclosure risk.

- **No sensitive values in URLs or error output — PASS**
  - Secrets and codes are not placed into URL query strings.
  - Generic server error messages are used.
  - The provisioning URI contains the secret only in an API response intended for authenticator setup, not a URL navigation/query string.

## FAILING_ITEMS

- The session cookie lookup in `current()` is syntactically valid JavaScript but semantically wrong: `.__Host-mfa_session` is parsed as property access followed by subtraction from an undeclared `mfa_session` variable. This causes a runtime `ReferenceError` and makes bootstrap and sign-in fail.

- `/api/mfa/existing/verify` consumes the request JSON body twice. The second read fails for a normal submitted code and returns a 500 response, making the existing-authenticator/recovery-code challenge unusable.

- The custom QR implementation does not reserve QR format-information cells before placing payload data. It subsequently overwrites payload modules with format bits, so the QR code cannot be considered valid or reliably scannable.

- The persistent visible “Logs” panel displays identity OTPs and recovery codes. Test values must be sent to and logged via the browser console as required, but they should not remain exposed in an in-page log after the relevant recovery/setup screen.

## NEW_TASKS

1. Fix `current()` to read the cookie only with bracket notation, for example:
   ```ts
   const cookies = parseCookies(request);
   const id = cookies["__Host-mfa_session"];
   ```
   Remove the invalid `.__Host-mfa_session` expression entirely. Verify `/api/bootstrap`, `/api/signin`, authenticated routes, and logout work with the emitted cookie.

2. Fix `/api/mfa/existing/verify` to parse the body exactly once, store it in a local variable, validate its `code` field, and use that stored value for TOTP/recovery-code handling.

3. Replace or repair `qrSvg()` so it generates a standards-compliant QR code. At minimum, reserve all format-information modules before payload placement, preserve the correct payload bit count/interleaving, and test that the generated `otpauth://` URI scans successfully with a QR reader.

4. Remove the persistent rendered sensitive-value log panel, or ensure it contains only non-sensitive status messages. Retain required academic test output through browser `console.log` only, while keeping recovery codes visible only on the dedicated recovery-code screen and while the user has chosen to reveal them.

## DECISION

FAIL