## SUMMARY

The artifact is a single `app.ts` Bun/TLS application with substantial MFA functionality, server-side session ownership checks, CSRF checks, encrypted OTP-secret storage, hashed recovery codes, rate limiting, security headers, and a mobile-oriented accessible UI. However, it does not fully meet the requirements because the displayed “QR code” is not a valid QR encoding of the provisioning URI and therefore cannot be scanned by an authenticator app. It also fails for the required IPv6 localhost origin (`https://[::1]:PORT`) because the trusted-origin check does not normalize bracketed IPv6 hostnames. The on-page sensitive “Logs” panel is also an unnecessary security and UX exposure.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun implementation with no frameworks, bundlers, compilers, or external assets**
  - The full server, HTML, CSS, and browser JavaScript are contained in `app.ts`.
  - The application uses `Bun.serve`, inline HTML/CSS/JS, and Node-compatible built-in crypto/fs modules only.
  - TLS certificates are loaded from `certs/cert.pem` and `certs/key.pem`.

- **PASS — Bun server uses TLS and secure session cookies**
  - `Bun.serve` is configured with certificate and key files.
  - Session cookies include `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, and an absolute lifetime.
  - Sessions have idle and absolute expiry handling, and session IDs are rotated after identity verification.

- **PASS — Server-side authorization and IDOR prevention for authenticated MFA actions**
  - Protected MFA routes resolve the account from the authenticated server-side session through `owner(request)`.
  - No endpoint accepts a user/account identifier from the client for MFA changes.
  - MFA enrollment, confirmation, backup regeneration, recovery-code verification, and logout are session-protected.

- **PASS — CSRF protection is implemented for state-changing actions**
  - State-changing endpoints require `X-CSRF-Token`.
  - The token is held in browser runtime state rather than browser storage.
  - The token is checked with `timingSafeEqual`.
  - SameSite cookies and origin validation add further CSRF protection.

- **FAIL — The QR-code option is not a real scannable provisioning QR code**
  - `qr(payload)` creates a pseudo-random visual grid based on the provisioning URI, but it does not implement QR encoding, error correction, finder patterns, or payload serialization.
  - The resulting image is labelled as an authenticator setup QR code but cannot be scanned by a normal authenticator application.
  - This violates the requirement to offer a usable QR-code provisioning option.

- **PASS — Manual authenticator-secret setup and copy-to-clipboard are available**
  - The authenticator seed can be revealed, hidden, and copied.
  - A valid `otpauth://totp/...` provisioning URI is generated server-side.
  - The TOTP verification logic accepts current adjacent time windows and prevents reuse of an accepted enrollment time-step.

- **PASS — Identity, authenticator, and recovery-code verifications work server-side**
  - Identity codes are six digits, expire, are single-use, and are rate-limited/locked after repeated failures.
  - TOTP verification validates six-digit codes with a time window and single-use enrollment step tracking.
  - Recovery codes are validated, expire, are single-use, and have rate-limit/lockout behavior.

- **PASS — Sensitive values are protected at rest**
  - OTP secrets are encrypted with AES-256-GCM.
  - Backup codes are generated from cryptographic randomness and stored as PBKDF2 hashes with a pepper.
  - Session tokens, OTP secrets, and recovery hashes are not persisted in localStorage, sessionStorage, or JavaScript-readable cookies.

- **PASS — Secure response headers and restrictive CSP are present**
  - CSP includes nonce-based script/style authorization, `frame-ancestors 'none'`, `base-uri 'none'`, and `connect-src 'self'`.
  - HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, referrer policy, permissions policy, and no-store cache headers are set.
  - Error responses are generic and do not expose stack traces.

- **FAIL — Required IPv6 localhost usage is broken by trusted-origin validation**
  - The requirements explicitly provide TLS certificates for `localhost`, `127.0.0.1`, and `::1`.
  - For an origin such as `https://[::1]:3000`, `new URL(origin).hostname` is normally bracketed (`[::1]`), but the allow-list checks only `"::1"`.
  - Consequently, same-origin POSTs opened through the IPv6 localhost address can fail `trusted(request)` and be rejected by CSRF/origin checks.

- **PASS — Mobile and dyslexia-aware UI design is largely implemented**
  - The UI is responsive, constrained to a mobile-friendly width, uses generous spacing, readable font sizes, visible focus styles, short instruction text, examples, icons, and predictable steps.
  - The flow has no animations, countdowns, or auto-updating interface elements.
  - Inputs support relevant `autocomplete`, `inputmode`, and one-time-code hints.
  - Error messages explain the problem and corrective action.

- **FAIL — The visible in-page “Logs” panel unnecessarily exposes sensitive mock values and adds clutter**
  - The `logs()` function renders a persistent panel containing mock identity codes, authenticator OTPs, and backup recovery codes.
  - Browser `console.log` is required for the academic mock/testing behavior, but rendering those values persistently in the application UI is not required.
  - This creates avoidable visual clutter and leaves sensitive recovery codes visible while navigating between screens, conflicting with the secure-storage and low-clutter UX goals.

- **PASS — Internal flow navigation functions without external links or redirects**
  - Navigation between sign-in, identity verification, enrollment, backup-code management, recovery verification, home, and logout is handled in the SPA.
  - No client-controlled redirects or external navigation are present.

## FAILING_ITEMS

- The visual QR pattern generated by `qr(payload)` is not a standards-compliant QR code and cannot provision an authenticator app from the generated `otpauth://` URI.
- IPv6 localhost origin validation is incorrect: `[::1]` is not accepted even though `::1` is listed as trusted, causing protected POST requests to fail when the site is opened via IPv6.
- The UI renders a persistent sensitive “Logs” panel containing mock OTPs and backup codes. Browser-console logging can remain for the testing requirement, but these values should not remain displayed across screens.

## NEW_TASKS

1. Replace the custom pseudo-random `qr(payload)` renderer with an embedded, dependency-free standards-compliant QR encoder that encodes `S.uri`, produces a scannable QR matrix, and remains entirely within `app.ts`.
2. Normalize IPv6 hostnames in `trusted(request)` before allow-list comparison, such as by converting bracketed `[::1]` to `::1`, and verify that same-origin POST requests work from `https://[::1]:PORT`.
3. Remove the rendered `logs()` panel and its invocation from `render()`, while retaining the required browser-side `console.log` statements for mock identity codes, OTPs, and recovery codes.

## DECISION

FAIL