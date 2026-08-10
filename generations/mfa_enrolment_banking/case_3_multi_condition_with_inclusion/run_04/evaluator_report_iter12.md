## SUMMARY

The artifact is a single-file Bun/TypeScript MFA enrolment SPA with a generally strong mobile UI, CSRF protection, secure cookie attributes, server-side session ownership checks, encrypted authenticator secrets, hashed recovery codes, TLS configuration, deterministic browser-side test mocks, and functioning enrolment/recovery flows. However, it fails the security acceptance requirements because verification lockouts can be bypassed by requesting replacement codes/details, and sensitive provisioning data is intentionally written into browser/UI logs.

## FUNCTIONAL_CHECK

- **Single `app.ts` file containing Bun server, HTML, CSS, and vanilla browser JavaScript — PASS**
  - The supplied artifact is one `app.ts` file and embeds the page template, CSS, browser JS, and Bun server.

- **No frameworks, bundlers, compilation pipeline, external assets, or external network calls — PASS**
  - The implementation uses native Bun APIs and browser APIs only. The QR code is generated locally and no third-party scripts, fonts, images, APIs, or CDN assets are used.

- **Bun TLS server using supplied certificate paths — PASS**
  - `Bun.serve()` is configured with `certs/cert.pem` and `certs/key.pem`.
  - Cookies use `Secure`, and HSTS is returned.

- **Responsive, legible mobile UI with dyslexia-conscious content and layout — PASS**
  - The UI has a constrained mobile layout, large form controls, adequate spacing, plain language, short instructions, examples for expected input, no animation, and expandable help text.
  - The step indicator and primary action are prominent.

- **Identity verification, authenticator setup, backup-code generation, and recovery-code verification work — PASS**
  - Test mode provides deterministic values:
    - Identity OTP: `123456`
    - Authenticator code: `654321`
    - Recovery codes: deterministic list
  - Identity OTP is cleared after successful verification.
  - Pending authenticator setup is cleared after enrolment.
  - Recovery codes are hashed and removed after successful use.

- **QR code and manual authenticator setup option — PASS**
  - The UI provides an inline QR code and a manual setup secret.
  - The manual secret has a copy-to-clipboard control.
  - The provisioning URI is also generated server-side.

- **Copy/reveal/hide/regenerate recovery-code workflow — PASS**
  - Recovery codes can be copied, hidden, revealed, and regenerated.
  - Replacement-code messaging clearly states that previous codes stop working.

- **Server-side authorization and IDOR prevention — PASS**
  - MFA endpoints use the server-side cookie session and `owner()` checks.
  - The authenticated account identity is server-controlled; no client-provided user ID is trusted.

- **CSRF protection for state-changing operations — PASS**
  - State-changing API routes require the per-session `x-csrf-token`.
  - The token is rotated after successful identity verification.

- **Security headers, secure cookie attributes, and restrictive CORS — PASS**
  - CSP, HSTS, `X-Content-Type-Options`, `X-Frame-Options`, referrer policy, permissions policy, and origin allow-list handling are implemented.
  - Session cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`.

- **Secrets protected at rest — PASS**
  - Authenticator secrets are AES-GCM encrypted in the in-memory session object.
  - Recovery codes are SHA-256 hashed with a server-generated pepper.
  - Production identity codes are stored as hashes.

- **Input validation and output encoding — PASS**
  - Email, password, OTP, and recovery-code inputs are server-side validated with bounded lengths and explicit format checks.
  - Browser-rendered dynamic values are escaped before insertion into HTML.

- **Verification codes are time-bound and single-use — PARTIAL / FAIL**
  - Identity OTPs expire and are cleared after successful verification.
  - Pending authenticator setup expires and is cleared after successful enrolment.
  - Recovery codes are single-use.
  - However, the configured failed-attempt lockouts are bypassable, so the rate-limiting/lockout acceptance requirement is not met.

- **Rate limiting and lockout after repeated failed verification attempts — FAIL**
  - `issueIdentity()` calls `resetAttempts(s, "identity")`.
  - `/api/identity/send` calls `issueIdentity()` even when `identityLocked` is active.
  - `/api/authenticator/start` calls `resetAttempts(o, "otp")` even when an OTP lock is active.
  - `/api/backup/generate` and `/api/backup/regenerate` call `resetAttempts(o, "recovery")` even when a recovery lock is active.
  - An attacker can submit fewer than five failed attempts, request new details, and repeat indefinitely, or can bypass an active ten-minute lock immediately.

- **Do not expose OTP seeds, OTPs, backup codes, or session tokens in logs — FAIL**
  - In test mode, `details()` executes:
    - `log("[TEST ONLY] Provisioning URI: "+d.provisioningUri)`
  - The provisioning URI contains the authenticator shared secret and is written to both `console.log` and the visible `#logs` page panel.
  - The `log()` helper also writes test OTPs and recovery codes into the visible in-page “Logs” list. The testing requirement requires browser `console.log` output for deterministic mocks, but does not require an on-screen log pane containing sensitive data.
  - Logging a provisioning URI/OTP seed directly violates the requirement not to expose OTP seeds in logs.

- **Session fixation prevention, timeout, and logout invalidation — PASS**
  - Session IDs rotate after sign-in.
  - Idle and absolute timeouts are implemented.
  - Logout deletes the server-side session and expires the cookie.

- **Generic server error handling and no verbose stack traces — PASS**
  - The fetch handler catches errors and returns a generic message.
  - Server code does not log secrets or stack traces.

## FAILING_ITEMS

- **Verification lockout can be bypassed through replacement requests.**
  - A locked identity-verification session can call `/api/identity/send`, which resets `identityFails` and clears `identityLocked`.
  - A locked authenticator-verification session can call `/api/authenticator/start`, which resets `otpFails` and clears `otpLocked`.
  - A locked recovery-code-verification session can call `/api/backup/generate` or `/api/backup/regenerate`, which resets `recoveryFails` and clears `recoveryLocked`.
  - This defeats the stated five-attempt lockout and ten-minute waiting period.

- **Authenticator provisioning URI, including the OTP seed, is logged in the browser.**
  - `details()` logs `d.provisioningUri`, which embeds the shared TOTP secret.
  - The custom `log()` function additionally renders this sensitive value into the visible UI log panel.

- **The visible `Logs` panel unnecessarily exposes test OTPs and recovery codes on-screen.**
  - Browser-console test logging can remain limited to explicit test mode to meet the testing requirement.
  - Rendering sensitive test values in the page itself adds unnecessary exposure and visual clutter.

## NEW_TASKS

1. **Preserve verification lockouts when replacement codes/setup details are requested.**
   - Before `/api/identity/send`, `/api/authenticator/start`, `/api/backup/generate`, and `/api/backup/regenerate`, clear expired locks and reject the request with HTTP 429 if the applicable lock is still active.
   - Do not call `resetAttempts()` merely because a new code or setup secret is issued.
   - Only reset failed-attempt counters after a successful verification, or after the configured lock duration has elapsed.

2. **Remove provisioning URI / OTP-seed logging.**
   - Delete `log("[TEST ONLY] Provisioning URI: "+d.provisioningUri)` from `details()`.
   - Do not log the manual setup secret, TOTP seed, or full provisioning URI anywhere.

3. **Remove the in-page sensitive log viewer while retaining required test-console mocks.**
   - Remove the `#logs` / `#loglist` markup and related CSS.
   - Change `log()` to use only `console.log(...)`.
   - Keep deterministic identity OTP and recovery-code console output restricted to explicit test mode, as required for testing.

## DECISION

**FAIL**