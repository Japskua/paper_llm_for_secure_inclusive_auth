## SUMMARY

The artifact is a single-file Bun HTTPS application with a well-structured mobile UI, strong baseline headers, HttpOnly secure cookies, session expiry, CSRF checks on authenticated mutations, input validation, encrypted OTP-secret storage, hashed recovery codes, and clear dyslexia-aware presentation. However, it cannot complete its normal browser flow because its allowed-origin list omits port `3000`, causing same-origin POST requests to be rejected. It also provides a decorative pseudo-QR pattern rather than a scannable provisioning QR code, and its “authenticator” verification is a server-generated static challenge rather than a time-based OTP derived from the provisioned secret.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no framework, external assets, bundler, or build tool**
  - The complete server, HTML, CSS, and browser JavaScript are contained in `app.ts`.
  - `Bun.serve` is used directly with TLS certificate files from `certs/cert.pem` and `certs/key.pem`.

- **FAIL — The normal browser enrolment flow functions correctly**
  - Browser `fetch()` POST requests from `https://localhost:3000` send `Origin: https://localhost:3000`.
  - `allowedOrigins` only contains `https://localhost`, `https://127.0.0.1`, and `https://[::1]`, without port `3000`.
  - Consequently, `validOrigin()` rejects legitimate requests with HTTP 403 before sign-in can complete.

- **PASS — Mobile-responsive, dyslexia-aware UX is largely implemented**
  - The app uses a narrow mobile shell, readable default font stack, increased line/letter spacing, clear focus styling, short instructions, examples, generous input sizing, static screens, visible progress, and concise help text.
  - The interface avoids auto-updating visual elements and gives clear recovery/retry actions.

- **FAIL — Offered QR-code provisioning option is functional**
  - The `qrPattern()` function creates a decorative 13×13 visual pattern based on character codes. It does not encode the `otpauth://` URI as a real QR code and cannot be scanned by authenticator apps.
  - Labelling it “QR-style provisioning panel” does not meet the requirement to offer a working QR-code option.

- **FAIL — Authenticator verification implements time-based OTP**
  - `/api/mfa/provision` creates `session.authenticatorChallenge = createChallenge()`, which is a random six-digit static value valid for ten minutes.
  - `/api/mfa/verify` verifies that static value through `verifyChallenge`; it does not calculate a TOTP from the provisioned shared secret, time step, algorithm, digits, and period in the provisioning URI.
  - An authenticator app configured with the supplied provisioning URI would therefore not produce a code accepted by the server.

- **PASS — Manual alternatives and clipboard support are present**
  - The app exposes a manual secret, a provisioning-link copy action, manual six-digit code entry, recovery-code display, and copy/print actions.
  - OTP fields use `autocomplete="one-time-code"` and appropriate numeric input hints.

- **FAIL — Provisioning and recovery UI state is preserved reliably**
  - Entering the setup screen always calls `/api/mfa/provision`.
  - The generic `copy()` helper calls `render(current, ...)`; on the setup screen this causes another provisioning request and silently replaces the previous secret/server challenge.
  - A user who copied or entered the prior secret could be left with a changed provisioning secret.
  - On the recovery screen, `copy()` also rerenders the screen but does not call `fillCodes()`, so already generated codes disappear from the visible panel despite remaining in memory/server state.

- **PASS — Server-side session ownership and IDOR defenses exist on protected MFA endpoints**
  - Protected endpoints require a valid opaque session cookie and use the session’s server-held `userId`.
  - State requests reject a supplied `userId` if it differs from the authenticated session user.
  - No endpoint accepts an arbitrary account identifier to load or modify another account’s MFA settings.

- **PASS — CSRF and session-cookie controls are substantially implemented**
  - Authenticated state-changing requests require `X-CSRF-Token` matching the server-held session token.
  - Session cookies use `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - Session identifiers are regenerated during sign-in, have idle and absolute expiry checks, and are invalidated on logout.

- **PASS — Secure HTTP response headers and HTTPS are configured**
  - The artifact sets CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, referrer policy, permissions policy, and `Cache-Control: no-store`.
  - Bun is configured to serve TLS using the required certificate paths.
  - Generic catch handling avoids sending stack traces to clients.

- **FAIL — Trusted-origin/CORS handling works in the served deployment**
  - While the intended policy is restrictive, it rejects the app’s own served origins due to the missing port.
  - The same defect affects both normal API POSTs and CORS preflight handling.

- **PASS — Input validation and output encoding are generally sound**
  - Email, OTP, and recovery-code formats are server-validated.
  - Client-rendered dynamic strings are escaped with `esc()` or placed using `textContent`.
  - No SQL/database layer is present, so parameterized-query requirements are not applicable to this implementation.

- **PASS — Code expiry, single use, failed-attempt limits, and lockout are implemented for mock challenges**
  - Identity and static authenticator challenges expire, become single-use after success, track failures, and lock after five failed attempts.
  - Recovery codes are hashed and deleted after successful use.

## FAILING_ITEMS

- Legitimate same-origin API calls from the Bun server at `https://localhost:3000`, `https://127.0.0.1:3000`, or `https://[::1]:3000` are rejected because `allowedOrigins` does not include the port.
- The QR panel is not a valid QR code and cannot provision an authenticator app.
- The authenticator flow is not TOTP: the supplied `otpauth://totp/...` URI and server verification behavior do not match.
- Copying a provisioning link or secret rerenders setup and generates a new provisioned secret/challenge, invalidating the prior setup state.
- Copying recovery codes rerenders the recovery page without restoring its generated-code panel, making the already generated codes disappear from the UI.

## NEW_TASKS

1. Update origin validation and CORS handling to allow only the exact deployed HTTPS origins including port `3000` (`https://localhost:3000`, `https://127.0.0.1:3000`, and `https://[::1]:3000`), while continuing to reject all other origins.

2. Replace the decorative `qrPattern()` output with a standards-compliant, scannable QR code encoding the exact returned `otpauth://` provisioning URI, implemented within `app.ts` without external network assets.

3. Implement real simulated TOTP verification: derive the current six-digit code from the encrypted provisioned secret using the URI’s SHA-1, 30-second period, and six-digit settings; permit an appropriate clock-skew window; and track accepted time steps to enforce one-time use where required.

4. Keep a provisioned secret/challenge stable until the user explicitly chooses “Start with a new set-up code.” Do not re-provision when displaying success feedback after copy actions or other UI rerenders.

5. Preserve generated recovery-code display state across UI rerenders, including after copy feedback, so generated codes and acknowledgement/finish controls remain visible until the user explicitly regenerates, finishes, or leaves the screen.

## DECISION

FAIL