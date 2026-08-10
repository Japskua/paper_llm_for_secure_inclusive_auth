## SUMMARY

The artifact is a single `app.ts` Bun application with a functional HTTPS MFA enrolment flow, server-side session ownership checks, CSRF checks, encrypted OTP-secret storage, hashed backup codes, rate limiting, session rotation, and a responsive accessible UI. It has no apparent TypeScript syntax errors and does not use external assets or build tooling. However, it does not provide a real scannable QR code, exposes sensitive mock values in a persistent in-page log, and does not let the user directly regenerate a provisioning setup key after it has been created.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun implementation with no frameworks, external assets, bundlers, or compilation step**
  - The full server, HTML template, CSS, and browser JavaScript are contained in `app.ts`.
  - It uses Bun directly and only Node built-in crypto APIs.
  - TLS is configured with `certs/cert.pem` and `certs/key.pem`.

- **PASS — Responsive, mobile-legible, dyslexia-conscious UI**
  - The page has a mobile viewport meta tag, constrained mobile layout, generous spacing, readable font sizing, clear headings, icons, visible focus states, plain-language instructions, input examples, and no animation or automatic updates.
  - OTP inputs use `inputmode="numeric"` and `autocomplete="one-time-code"`.

- **PASS — Identity verification flow works**
  - The user can mock-sign-in, request an identity code, see the mock value, enter it, and proceed.
  - Identity codes are time-bound, single-use, HMAC-protected server-side, and invalidated after use.
  - Failed attempts are rate-limited and can trigger a lockout.

- **PASS — Authenticator OTP verification works**
  - A provisioning secret is generated with cryptographically secure randomness.
  - The secret is AES-256-GCM encrypted at rest.
  - TOTP verification accepts a bounded time window and prevents reuse of the accepted TOTP counter.
  - The mock current OTP is returned to the UI and emitted with browser-side `console.log`, as required for testing.

- **FAIL — QR-code option is not a usable authenticator QR code**
  - `fakeQr()` creates a deterministic-looking visual grid but does not encode the `otpauth://` provisioning URI returned by `/api/provision`.
  - Scanning the displayed image cannot provision an authenticator application.
  - The requirement calls for QR-code support and specifically requires that a QR/provisioning option correspond to a usable manual secret/code path. A visible setup key exists, but the QR option itself is misleading and non-functional.

- **PASS — Manual provisioning-secret path and clipboard support are present**
  - The setup secret can be shown, hidden, and copied to the clipboard.
  - Backup recovery codes can be shown, hidden, copied, and regenerated.
  - The provisioning API returns an `otpauth://` URI, though it is currently not rendered or copied by the UI.

- **PASS — Backup-code generation and MFA completion are enforced server-side**
  - Backup codes are generated from secure random bytes.
  - Only salted `scrypt` hashes are retained on the server.
  - MFA cannot be marked enabled until a current enrolment has passed OTP verification and generated backup codes.

- **FAIL — Sensitive OTP and backup-code values are written into a persistent in-page log**
  - The `simulation()` function calls `log()`, and `log()` writes the values into `#logs`.
  - This causes identity OTPs, authenticator OTPs, and backup recovery codes to remain visible in the application’s persistent “Logs” panel.
  - The security requirements prohibit exposing OTPs and backup codes in logs. The requirements explicitly require browser `console.log` for mock testing, but they do not require a user-visible persistent log containing secrets.
  - The visible log also creates unnecessary visual clutter for the intended dyslexia-friendly UX.

- **FAIL — Setup-key regeneration/re-request is not directly available after provisioning**
  - Once `/api/provision` succeeds, the primary button changes from “Make setup key” to “Continue to check code.”
  - There is no direct “Make a new setup key” or “Re-request setup key” action on the provisioning screen.
  - The user can only restart the overall setup flow, which sends them back through identity verification rather than letting them retry the current provisioning step predictably.
  - This does not meet the requirement to let users retry steps and re-request codes without penalty.

- **PASS — Server-side authorization and IDOR protections**
  - Protected API routes derive the account ID exclusively from the `HttpOnly` session.
  - No user/account identifier is accepted from client input for MFA records.
  - `requireOwner()` verifies a live session and fixed authenticated account ownership on protected requests.

- **PASS — CSRF and origin protections for state changes**
  - State-changing protected POST endpoints require both a trusted `Origin` and a session-specific CSRF token.
  - The mock-login endpoint requires a trusted browser origin before creating a session.
  - Session cookies are `HttpOnly`, `Secure`, `SameSite=Strict`, and scoped to `/`.

- **PASS — Secure server configuration**
  - Responses include CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, no-cache headers, a restrictive referrer policy, and a permissions policy.
  - Server exceptions return a generic message rather than stack traces.
  - CORS preflight is restricted to configured local trusted origins.

- **PASS — Validation and output encoding**
  - Phone suffixes, OTP values, and recovery-code format are validated server-side.
  - Dynamic HTML values are escaped client-side through `esc()`.
  - The application has no external redirects and no user-controlled redirect target.

- **PASS — Secure session lifecycle**
  - Sessions have idle and absolute expiry.
  - The session identifier is rotated after identity verification.
  - Logout invalidates the server session and expires the cookie.

## FAILING_ITEMS

- The visible “Mock authenticator setup QR code” is not a real QR encoding of the `otpauth://` provisioning URI and therefore cannot be scanned by an authenticator app.
- OTPs and backup recovery codes are copied into the persistent in-page `#logs` element, violating the prohibition on exposing those values in logs and adding unnecessary UI clutter.
- The authenticator provisioning screen lacks a direct retry/regenerate/re-request setup-key action once a setup key has been generated.

## NEW_TASKS

1. Replace `fakeQr()` with a standards-compliant QR renderer that encodes the exact `uri` returned from `/api/provision`; render that QR code on the setup screen and provide a copy action for the provisioning URI and/or setup key.
2. Remove the persistent user-visible `Logs` panel and stop writing OTPs and backup recovery codes into page DOM logs; retain the required browser `console.log` mock output only.
3. Add a clearly labelled secondary action on the authenticator provisioning screen, such as “Make a new setup key,” which calls `/api/provision` again and replaces the prior setup key, QR code, and mock OTP without requiring the user to restart identity verification.

## DECISION

FAIL