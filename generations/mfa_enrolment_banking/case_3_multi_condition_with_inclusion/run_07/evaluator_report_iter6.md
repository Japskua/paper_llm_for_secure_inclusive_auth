## SUMMARY

The artifact is a single-file Bun HTTPS SPA with substantial security and UX coverage: authenticated sessions, CSRF checks, encrypted OTP seed storage, hashed recovery codes, rate limiting, mobile styling, copy controls, accessible status messages, and browser-console mock output are implemented. However, it does not fully meet the requirements because the advertised QR code is not a valid QR code, IPv6 localhost requests are rejected by origin validation, and login rate limiting can be bypassed by spoofing `X-Forwarded-For`. The demo sign-in credential is also not presented to the user, making the initial flow impractical without inspecting source code or external knowledge.

## FUNCTIONAL_CHECK

- **FAIL — Single-file Bun server with HTML, CSS, and vanilla client JavaScript**
  - `app.ts` contains the Bun server, HTML template, inline CSS, and inline browser JavaScript. No framework, bundler, or external asset is used.
  - However, this criterion is not sufficient for an overall pass because other required functionality is defective.

- **PASS — HTTPS/TLS server uses the required certificate paths**
  - `Bun.serve` is configured with `tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") }`.
  - The app listens via HTTPS and sets HSTS.

- **FAIL — Authenticator provisioning provides a usable QR-code option**
  - The UI says “Scan this QR code,” but `qr(text)` draws a deterministic pseudo-random pattern on a canvas. It does not implement QR encoding, QR error-correction data, format/version information, masking, or URI payload encoding.
  - An authenticator application cannot scan this image to obtain the supplied `otpauth://` URI.
  - Copying the setup URI and manual secret work, but that does not make the offered QR option functional.

- **PASS — Manual setup-key alternative is available**
  - The server returns an `otpauth://` URI and Base32 secret after setup.
  - The UI offers “Copy setup link” and “Copy manual key,” allowing users to avoid manual transcription.

- **PASS — OTP and practice/mock verification work**
  - Real TOTP verification uses HMAC-SHA1 and a 30-second TOTP step with a small allowed time window.
  - OTP values are six digits, time-bound through TOTP, and rejected after use through `acceptedTotpSteps` / `acceptedTotpCodes`.
  - The mock practice code is generated server-side, shown only after an authenticated CSRF-protected request, logged in the browser, can be re-requested, expires, and becomes single-use after verification.

- **PASS — Backup-code generation, display, copy, replacement, and verification work**
  - Eight recovery codes are generated with `crypto.getRandomValues`.
  - Only hashes of backup codes are retained server-side.
  - The UI supports copying, printing, hiding, regeneration, and checking one code before completion.
  - Used recovery-code hashes are deleted, making recovery codes single-use.

- **PASS — Dyslexia-aware mobile UX is substantially addressed**
  - The UI has generous spacing, readable mobile layouts, short instructions, examples, icons, visible progress, clear error messages, copy controls, password-manager/autofill attributes, no animations, and no reading timer.
  - Primary actions are visually prominent and the status area provides plain-language feedback.

- **FAIL — The sign-in flow is usable without source-code knowledge**
  - The UI asks for an “Account PIN” but gives no test/demo credential, recovery mechanism, or account-creation route.
  - The server defaults to a hard-coded credential (`482913`), but users cannot reasonably know it from the application UI.
  - This prevents a normal evaluator or user from beginning the enrolment flow without reading source code or setting `MFA_DEMO_PIN` externally.

- **PASS — Server-side MFA authorization prevents client-selected account access**
  - State is always retrieved for the fixed authenticated account through `stateForAccount()`.
  - The server rejects bodies containing `accountId`, `userId`, or `sessionId`.
  - Endpoints use the session account ID rather than accepting a user identifier from the browser.

- **PASS — CSRF protection is applied to state-changing authenticated actions**
  - State-changing endpoints require both a same-origin request and an `X-CSRF-Token` matching the server-held session token.
  - The session cookie is `HttpOnly`, `Secure`, and `SameSite=Strict`.

- **FAIL — Trusted-origin validation supports all stated localhost certificate hosts**
  - The requirements explicitly include `localhost`, `127.0.0.1`, and `::1`.
  - `trustedRequest()` compares `url.hostname` to `"::1"`, but URL hostname serialization for an IPv6 URL is normally bracketed (`"[::1]"`).
  - Consequently, requests made from `https://[::1]:3000` can be rejected with 403, preventing authentication and all state-changing actions on the IPv6 host.

- **FAIL — Login rate limiting is robust**
  - Login throttling uses `clientKey()`, which directly trusts the client-provided `X-Forwarded-For` header.
  - An attacker can submit a different `X-Forwarded-For` value per request and avoid the per-client login lockout.
  - `X-Forwarded-For` must only be trusted when set by a known reverse proxy; this Bun server is directly exposed in the stated configuration.

- **PASS — Security headers and restrictive browser policies are present**
  - The app sets CSP with nonces, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, `Permissions-Policy`, and `Cache-Control: no-store`.
  - CORS is not broadly permissive; it only advertises `https://localhost:3000`.

- **PASS — Secrets are not persisted in browser storage or non-HttpOnly cookies**
  - No `localStorage` or `sessionStorage` is used.
  - The session token is stored in an `HttpOnly; Secure; SameSite=Strict` cookie.
  - OTP seed and recovery code values are only held in browser memory while required by the setup flow.

- **PASS — Server-side input validation and safe client rendering are implemented**
  - Email, phone, PIN, OTP, and recovery-code formats are validated server-side.
  - The client escapes dynamically inserted secret/code values before HTML interpolation.
  - Server responses do not reflect raw user values into HTML.

- **PASS — Sessions have idle and absolute timeout handling and logout invalidation**
  - Session validation enforces a 20-minute idle timeout and 8-hour absolute timeout.
  - Logout removes the server-side session and expires the cookie.
  - Successful authentication creates a newly generated session identifier.

- **PASS — Generic sign-in errors reduce account enumeration**
  - Authentication failures use one generic message regardless of whether email or PIN was wrong.
  - The email/PIN comparison is only completed after format validation, and the user-facing message does not identify which field failed.

## FAILING_ITEMS

- The canvas “QR code” is not a standards-compliant QR code and cannot be scanned by authenticator applications.
- The initial sign-in screen does not disclose a valid test/demo credential or provide another usable way for an evaluator to authenticate.
- `trustedRequest()` likely rejects the required IPv6 local origin, `https://[::1]:3000`, because it compares against `"::1"` rather than the URL hostname representation.
- Login rate limiting is bypassable because the server accepts arbitrary client-supplied `X-Forwarded-For` values as the rate-limit key.

## NEW_TASKS

1. Replace the pseudo-random canvas renderer with a real, self-contained QR encoder that encodes the exact `otpauth://` URI and produces a standards-compliant, scannable QR code; keep the copyable URI and manual Base32 key alternatives.
2. Make the demo authentication path usable from the UI without exposing secrets in logs or URLs: provide a clearly labelled test credential hint appropriate for this simulated academic artifact, or implement an explicit server-provided demo authentication mechanism with equivalent protections.
3. Correct `trustedRequest()` to recognize `localhost`, `127.0.0.1`, and IPv6 loopback reliably, including bracketed IPv6 URL hostname handling for `https://[::1]:PORT`.
4. Remove direct trust in `X-Forwarded-For` for login throttling. Rate-limit using a server-observed client address, or only honor forwarded-address headers when a configured trusted reverse proxy supplied them.

## DECISION

FAIL