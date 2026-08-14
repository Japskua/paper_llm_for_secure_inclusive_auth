## SUMMARY

The artifact is a well-structured single-file Bun HTTPS MFA enrolment application with working simulated identity verification, TOTP setup, recovery-code generation/consumption, session rotation, lockouts, secure-cookie attributes, encrypted/hash-protected MFA material, responsive mobile UI, and browser-console test logs. However, it does not strictly restrict trusted origins: its origin allow-list accepts any HTTPS service on `localhost`, `127.0.0.1`, or `[::1]` at any port. This weakens the CORS and Origin-based CSRF protections and does not meet the requirement to restrict CORS to explicitly trusted origins.

## FUNCTIONAL_CHECK

- **PASS — Single-file delivery and zero-compilation compliance**
  - The complete Bun server, HTML, CSS, and browser-side vanilla JavaScript are contained in one `app.ts`.
  - There are no frameworks, external assets, build tools, bundlers, or external network calls.
  - Bun directly serves the generated HTML and runs the TypeScript file.

- **PASS — Mobile SPA and MFA enrolment UX**
  - The UI is responsive, uses mobile-friendly dimensions, semantic elements (`main`, `header`, `section`, `article`, `form`, `label`), and clear enrolment stages.
  - The flow supports sign-in, identity verification, authenticator secret generation, authenticator confirmation, recovery-code display/acknowledgement, regeneration, recovery-code verification, and logout.
  - Manual authenticator material is shown when provisioning is generated.

- **PASS — Browser-side deterministic mock delivery**
  - The identity code, authenticator secret, authenticator fixture code, and recovery codes are returned to the UI in test mode.
  - These values are logged via browser-side `console.log`, as required.
  - Secrets are not logged by server-side code.

- **PASS — MFA verification functionality**
  - Identity codes are time-bound, single-use, and the session ID is rotated after successful identity verification.
  - Provisioning expires after five minutes.
  - Authenticator confirmation validates a six-digit code.
  - Recovery codes are generated with `crypto.getRandomValues`, PBKDF2-hashed at rest, and removed after successful use.
  - Repeated failed identity, authenticator, and recovery-code attempts are rate-limited with lockouts.

- **PASS — Broken access control protections**
  - MFA endpoints use authenticated server-side sessions via `required()`.
  - MFA state is always retrieved using the session’s fixed `userId`; client-controlled user/account identifiers are not accepted.
  - This prevents straightforward IDOR and guessed-user-ID manipulation.
  - Sensitive state-changing MFA operations require a per-session CSRF token.

- **FAIL — CSRF and trusted-origin enforcement**
  - The CSRF helper accepts any missing `Origin` header: `(!o || trusted(o))`.
  - More importantly, `trusted()` allows every HTTPS origin on `localhost`, `127.0.0.1`, and `[::1]` with any port. For example, `https://localhost:4444` is trusted even when it is not the bank application.
  - A malicious or unrelated local HTTPS service on an arbitrary port can therefore satisfy the Origin check and receive CORS permission.
  - The requirement calls for CORS restricted to trusted origins, which should be an explicit, configured allow-list for the actual application origin(s), not all loopback ports.

- **PASS — Security response headers**
  - Responses set CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, and `Permissions-Policy`.
  - The HTML response uses a per-response CSP nonce for its inline script and style.
  - API and HTML responses use `Cache-Control: no-store`.

- **PASS — Session security**
  - Session cookies include `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - The server only runs with TLS configured from `certs/cert.pem` and `certs/key.pem`.
  - Sessions have idle and absolute expiration.
  - Sessions are invalidated on logout.
  - The session identifier is replaced after successful identity verification.

- **PASS — Cryptographic storage and secret handling**
  - OTP secrets are AES-GCM encrypted before placement in the MFA store.
  - Recovery codes are stored as PBKDF2 verifiers with unique salts.
  - Secret generation uses cryptographically secure randomness.
  - The browser does not use `localStorage`, `sessionStorage`, or client-readable cookies for session or MFA secrets.

- **PASS — Input validation and output handling**
  - JSON request bodies use strict allow-lists for allowed properties.
  - Email, phone, OTP, identity-code, and recovery-code formats are validated server-side.
  - Client-side rendering of dynamic values uses `textContent` for values containing secrets, limiting DOM XSS exposure.
  - Redirect input is restricted to the fixed internal value `"/"`.

- **PASS — Generic error handling**
  - Errors return generic JSON error messages without stack traces or secret values.
  - The top-level request handler catches unexpected errors and returns a generic response.

## FAILING_ITEMS

- **Trusted origins are not explicitly restricted.**
  - `trusted()` accepts all HTTPS loopback origins at arbitrary ports:
    ```ts
    /^https:\/\/(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/i
    ```
  - This is too broad for both CORS and Origin-based CSRF validation. A separate local service at `https://localhost:<attacker-port>` is treated as trusted.

- **CSRF Origin validation permits requests with no `Origin` header.**
  - The CSRF validation currently allows an absent Origin:
    ```ts
    return (!o || trusted(o)) && ...
    ```
  - State-changing JSON API requests should require the exact configured same-origin Origin value where browser Origin validation is being used as a CSRF control.

## NEW_TASKS

1. Replace the regex-based arbitrary-port `trusted()` function with an explicit allow-list built from the configured application HTTPS origin, such as `https://localhost:${port}`, plus only specifically required loopback aliases if they are intentionally supported.

2. Update CORS handling so `Access-Control-Allow-Origin` and credentialed CORS headers are returned only when the request Origin exactly matches an entry in that explicit allow-list.

3. Update `csrf()` to require an exact trusted `Origin` for all state-changing API requests rather than accepting a missing Origin header.

4. Ensure the client’s served origin is included in the explicit allow-list for the configured `PORT`, and document any intentionally supported alternate local origins.

## DECISION

**FAIL**