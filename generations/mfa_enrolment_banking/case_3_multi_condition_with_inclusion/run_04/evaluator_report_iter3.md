## SUMMARY

The artifact is a single-file Bun application with a responsive, accessible MFA flow and many strong security controls (TLS, secure cookies, CSP, CSRF tokens, authorization checks, encrypted OTP seed storage, hashed recovery codes, and OTP/recovery-code lockouts). However, it has critical functional and security defects: the server’s OTP algorithm is incompatible with the `otpauth://` QR/manual secret it provides, the displayed default identity details let any visitor authenticate as Marcus, and the required browser-visible deterministic mock logging is only conditionally available and is not deterministic. Therefore the artifact cannot be accepted.

## FUNCTIONAL_CHECK

- **FAIL — Single-file Bun server with HTML, CSS, and vanilla browser JavaScript**
  - `app.ts` contains the Bun server and generated HTML/CSS/JS, with no framework, bundler, or external runtime assets.
  - However, single-file compliance alone does not overcome the functional/security failures below.

- **PASS — TLS configuration uses the specified certificate paths**
  - The server reads `certs/cert.pem` and `certs/key.pem` and configures `Bun.serve({ tls: { cert, key } })`.
  - It also emits HSTS.

- **PASS — Responsive and dyslexia-conscious mobile UI**
  - The page has a mobile viewport meta tag, constrained mobile layout, readable base font sizing, increased letter/line spacing, high-contrast focus styles, plain-language text, icons, generous spacing, and no moving/flashing content.
  - Each screen has a clear primary action and persistent short help text.

- **PASS — No browser persistence of secrets or session tokens**
  - The client does not use `localStorage`, `sessionStorage`, or non-HttpOnly cookies.
  - Provisioning/recovery values are held in JavaScript memory and cleared on completion.

- **FAIL — Authenticator QR/manual setup can be verified by a real compatible authenticator**
  - The generated provisioning URI is an `otpauth://totp/...` URI, which instructs authenticator apps to calculate standard TOTP values.
  - `makeOtp()` does **not** implement standard TOTP. It uses HMAC-SHA-256 over `String(step)` rather than the required HMAC over an 8-byte big-endian moving counter, and it does not use standard dynamic truncation.
  - Therefore, codes from an authenticator app that scans the QR code or receives the copied secret will not match the server’s verification codes.

- **FAIL — Manual provisioning option is actually usable without transcription/copy support**
  - The UI offers only a “Copy manual secret” button. It never displays a revealable manual secret for the user to enter into an authenticator app if clipboard access is unavailable or undesired.
  - On copy failure, the only option is to “try again”; the user cannot read or manually use the secret.
  - This does not fully meet the requirement to support the manual equivalent when QR provisioning is offered.

- **FAIL — Simulated OTP/recovery mocks are returned to the UI and logged in the browser as required**
  - The current OTP is returned and browser-logged only when `MFA_DEMO_ONLY === "true"`.
  - In normal operation, no mock OTP is returned to the UI or logged to the browser console.
  - Recovery codes are shown in the UI, but browser console logging is also limited to demo mode.
  - The demo OTP is not deterministic: it depends on a random secret and the current five-minute time step.

- **FAIL — Identity verification securely authenticates the account owner**
  - The sign-in form pre-populates the exact valid credentials:
    - `marcus@example.test`
    - `5550100`
  - Any unauthenticated visitor can load the page and click “Confirm identity” to receive an authenticated session for Marcus.
  - This violates the requirement that only the authenticated account owner may view or modify MFA settings and makes all subsequent MFA authorization ineffective.

- **FAIL — Repeated failed identity-verification attempts are rate-limited/locked**
  - OTP and recovery-code failures are rate-limited and locked after five failures.
  - `/api/signin` has no attempt counter, rate limit, or lockout. It allows unlimited repeated credential guessing attempts.

- **PASS — Server-side authorization and IDOR resistance for protected MFA routes**
  - Protected MFA routes derive identity exclusively from the session (`requireOwner`), not from a submitted user identifier.
  - There are no user-ID parameters that can be manipulated to access another account’s MFA data.
  - `/api/provision`, OTP verification, recovery-code operations, and logout all require the owner session where appropriate.

- **PASS — CSRF and origin protections for state-changing requests**
  - State-changing requests require an `X-CSRF-Token` matching the server-side session token.
  - Session cookies use `SameSite=Strict`.
  - Trusted origins are allow-listed and not reflected arbitrarily.

- **PASS — Secure cookie and response-header configuration**
  - Session cookies include `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - Responses include CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, no-store caching, and restrictive permissions/referrer policies.

- **PASS — Sensitive data handling at rest and in logs**
  - OTP seed material is AES-GCM encrypted in the in-memory MFA record.
  - Recovery codes are stored as peppered SHA-256 hashes and deleted after use.
  - The server does not log OTP seeds, OTPs, recovery codes, or session identifiers.
  - The production path does not expose raw exception stacks.

- **PASS — OTP and recovery-code single-use/expiry behavior**
  - OTP acceptance prevents reuse of an accepted time step.
  - OTP validation allows the current and previous time step and uses a five-minute time period.
  - Recovery codes are removed after successful use.
  - OTP and recovery-code failed-attempt lockouts are implemented.

- **PASS — Input validation, output encoding, and redirect safety**
  - Server-side validation exists for email, phone, OTP, and recovery-code formats.
  - Client-rendered dynamic messages are escaped through `esc()`.
  - There are no user-controlled redirects or external network calls.

## FAILING_ITEMS

- The OTP implementation is incompatible with the standard TOTP algorithm implied by the generated `otpauth://totp` provisioning URI. Real authenticator applications cannot successfully verify against this server.
- The identity-verification screen exposes the exact valid account email and phone number as pre-filled values, allowing any visitor to authenticate as Marcus and change MFA settings.
- `/api/signin` has no rate limiting or lockout for repeated failed identity-verification attempts.
- The required mock OTP and recovery-code browser-console behavior is conditional on `MFA_DEMO_ONLY=true`, unavailable by default, and the OTP value is time/random dependent rather than deterministic.
- The manual authenticator secret cannot be revealed/read in the UI; it can only be copied. Clipboard failure leaves no manual setup path.
- Recovery codes are generated client-side and accepted server-side as caller-provided values. This means the server does not guarantee that recovery codes are generated with its own cryptographically secure RNG.

## NEW_TASKS

1. Replace `makeOtp()` with a standards-compliant RFC 6238 TOTP implementation: HMAC-SHA-1 by default, an 8-byte big-endian counter, dynamic truncation, six digits, and the same period declared in the provisioning URI. Verify generated server test/mock codes with a standard authenticator-compatible implementation.

2. Replace the publicly pre-filled identity credentials with a secure simulated authentication mechanism that cannot let arbitrary visitors become Marcus. Keep the account identity server-controlled and issue the authenticated session only after valid simulated proof of identity.

3. Add server-side rate limiting and temporary lockout for failed `/api/signin` verification attempts, using a server-side key such as session plus account/IP context, and return a clear retry message.

4. Implement the required test/demo mock behavior in the browser: return the test OTP and recovery codes to the UI as appropriate, log them with `console.log` in the browser, and use documented deterministic test values/configuration that still allow verification to work.

5. Add a reveal/hide manual-secret control that displays the provisioning secret in a legible grouped format, alongside copy functionality. Keep the secret out of URLs, storage, and normal server logs.

6. Generate recovery codes server-side with `crypto.getRandomValues`, return them only once to the authenticated UI after recent authenticator confirmation, and store only their hashes. Remove acceptance of arbitrary client-generated recovery-code sets.

## DECISION

**FAIL**