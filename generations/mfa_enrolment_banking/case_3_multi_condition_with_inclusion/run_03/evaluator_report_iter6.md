## SUMMARY

The artifact is a well-structured single-file Bun HTTPS SPA with many strong security and accessibility measures, including secure cookies, CSP/HSTS, server-side session ownership checks, CSRF checks for authenticated mutations, encrypted OTP-secret storage, hashed recovery codes, input validation, and readable mobile-oriented UI. However, it has a functional routing bug that prevents MFA settings from loading, and its displayed “QR code” is not a real scannable QR code. The OTP also has no expiry/time-bound enforcement.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with inline HTML, CSS, and vanilla browser JavaScript**
  - The full server, page template, CSS, and client logic are contained in `app.ts`.
  - It uses `Bun.serve` directly and does not require a bundler, framework, external package, or external network resource.

- **PASS — Bun HTTPS server uses the required local TLS certificate locations**
  - `Bun.serve` is configured with:
    - `cert: Bun.file("certs/cert.pem")`
    - `key: Bun.file("certs/key.pem")`

- **PASS — Mobile-responsive, dyslexia-conscious UI**
  - The viewport meta tag is present.
  - The UI uses a legible sans-serif stack, increased letter spacing, comfortable line height, large controls, short instructions, examples, icons, generous spacing, and no animated or time-pressured UI.
  - The main content width is constrained for mobile layout.

- **PASS — Clear staged MFA enrolment flow**
  - The flow includes sign-in, identity confirmation, authenticator setup, OTP verification, recovery-code saving, completion, settings, and recovery-code verification.
  - Step indicators and status messages are provided.
  - Error messages explain the problem and corrective action.

- **PASS — Manual authenticator-key and OTP entry are supported**
  - The setup secret can be shown, hidden, and copied.
  - The OTP field supports manual six-digit entry with `autocomplete="one-time-code"` and an example.
  - Recovery codes can be copied and manually entered.

- **FAIL — The offered QR code is not a valid/scannable provisioning QR code**
  - The `qr(text)` function draws a custom pseudo-random checker pattern from URI bytes. It does not implement QR encoding, error correction, format/version information, masking, or data placement rules.
  - The setup screen says “Scan this square with your authenticator app,” but authenticator apps will not be able to scan the rendered canvas as an `otpauth://` URI.
  - This fails the requirement to offer a functional QR-code option when provisioning is offered.

- **FAIL — MFA settings cannot load due to GET request body handling**
  - In `handler`, all API routes other than `/api/signin` execute:
    - `const b = await body(r); if (!b) return fail();`
  - A `GET /api/settings` request has no JSON body, so `body(r)` returns `null` and the handler returns an error before reaching:
    - `if (r.method==="GET" && u.pathname==="/api/settings")`
  - The client’s `settings()` function therefore always fails and redirects the user back to sign-in with an error.
  - The “Open MFA settings,” “Back to settings,” and settings-based recovery-code flow do not function correctly.

- **PASS — Server-side authorization and IDOR prevention are substantially implemented**
  - Authenticated endpoints use the HttpOnly session cookie and retrieve the account only from `s.userId`.
  - Request-provided ownership fields such as `userId`, `accountId`, and `emailOwner` are rejected by `noId`.
  - No endpoint uses a client-provided account identifier to load or modify data.

- **PASS — Session security is substantially implemented**
  - Sessions are created with cryptographically random identifiers.
  - Existing supplied sessions are deleted when signing in and a new session is issued.
  - Idle and absolute session timeouts are enforced.
  - Logout invalidates the server-side session and clears the cookie.
  - Cookies use `HttpOnly`, `Secure`, and `SameSite=Strict`.

- **PASS — Authenticated state-changing endpoints use CSRF and same-origin checks**
  - `access()` verifies `b.csrf === s.csrf`.
  - It also checks the `Origin` header when present.
  - Authenticated mutation endpoints, including identity confirmation, provisioning, OTP verification, recovery-code generation, confirmation, recovery verification, and logout, go through `access()`.

- **FAIL — OTP verification is not time-bound**
  - `/api/mfa/verify` accepts the static `TEST_OTP` value `654321` indefinitely until it is used.
  - There is no issuance timestamp, expiry timestamp, TOTP period validation, or maximum validity window.
  - This does not meet the requirement that verification codes/OTPs be time-bound.

- **PASS — OTP and recovery-code single-use behavior and failed-attempt lockouts are implemented**
  - OTP setup is marked used after successful verification via `x.a.provision.used = true`.
  - A recovery code is removed after successful verification.
  - OTP and recovery-code failures are counted and locked for five minutes after five failures.

- **PASS — OTP secret and recovery codes have protected server-side storage**
  - The OTP secret is AES-GCM encrypted before being stored in account state.
  - Recovery codes are stored as salted PBKDF2 hashes rather than plaintext.
  - The server does not log secrets, OTPs, recovery codes, or session IDs.

- **PASS — Secure headers and cache controls are present**
  - Responses include CSP with nonces, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, and `Cache-Control: no-store`.

- **PASS — Input handling and client-side output handling are generally safe**
  - Email, phone, OTP, and recovery-code inputs are validated server-side.
  - Server-controlled and user-derived messages are inserted using `textContent`, not `innerHTML`.
  - There are no database queries or redirects that could introduce SQL injection or open-redirect behavior.

## FAILING_ITEMS

- **MFA settings are unusable:** `GET /api/settings` is rejected before its route handler because the server attempts to parse a JSON request body for every API request other than sign-in.
- **The QR canvas is not a real QR code:** the custom drawing algorithm cannot encode the provisioning URI into a scannable QR symbol, despite presenting it as an authenticator-app scan option.
- **OTP codes never expire:** the deterministic OTP remains valid indefinitely until used, rather than being time-bound as required.

## NEW_TASKS

1. Update API request routing so `GET /api/settings` is handled before JSON-body parsing, or parse request bodies only for methods that require them (`POST`, `PUT`, `PATCH`, etc.); retain session authorization for the settings endpoint.

2. Replace the custom `qr(text)` checker-pattern renderer with a real, self-contained QR encoder that generates a standards-compliant scannable QR code for the returned `otpauth://` provisioning URI. Keep the manual reveal/copy setup-key path.

3. Add OTP issuance and expiry state to provisioning, such as an `otpIssuedAt`/`otpExpiresAt` value, and reject OTP verification after the allowed mock validity window with a plain-language re-request instruction. Reissuing a setup key must create a fresh validity window.

## DECISION

FAIL