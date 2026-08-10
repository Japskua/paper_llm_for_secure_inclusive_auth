## SUMMARY

The artifact is a single-file Bun HTTPS MFA enrolment application with strong server-side session checks, CSRF protection, secure headers, encrypted OTP-secret storage, hashed recovery codes, rate limiting, and a functional browser UI. However, it does not fully meet the MFA setup and accessibility requirements because the displayed “QR code” is not a real scannable QR code, recovery-code guidance gives an invalid example, and form labels are not programmatically associated with their inputs.

## FUNCTIONAL_CHECK

- **PASS — Single-file, zero-compilation Bun application**
  - The server, HTML, CSS, and browser JavaScript are all contained in `app.ts`.
  - It uses `Bun.serve` directly, has no framework, bundler, compiler, package dependency, or external asset/network request.
  - It configures TLS with `certs/cert.pem` and `certs/key.pem`.

- **PASS — Responsive, mobile-oriented UI**
  - The HTML includes a mobile viewport meta tag.
  - The layout has a constrained mobile-width main column, readable text sizing, spacing, large controls, and a small-screen media query.

- **PASS — MFA enrolment flow and navigation**
  - The sign-in, identity check, authenticator provisioning, TOTP verification, recovery-code display, recovery-code use, regeneration, and logout flows are implemented.
  - The UI state transitions are functional and internal navigation is handled through working client-side views.

- **FAIL — QR-code provisioning option**
  - The `qr()` function draws a deterministic “QR-style” canvas pattern, but it is not a standards-compliant QR code encoding the `otpauth://` URI.
  - An authenticator application cannot scan this image to provision the account.
  - This fails the requirement to offer a usable QR-code option. The manual secret option does work, but it does not make the advertised QR option functional.

- **PASS — Manual authenticator setup option**
  - The app provides a reveal/hide manual Base32 secret, copy-to-clipboard support, and a copyable provisioning URI.
  - The user can manually enter the secret into an authenticator app rather than relying on QR scanning.

- **FAIL — Input examples are accurate and actionable**
  - The recovery-code input hint and placeholder use `ABCDE-FGHIJ`.
  - The server-side recovery-code alphabet explicitly excludes `I` (`RECOVERY_CHARSET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"`), so the displayed example is rejected by the validator.
  - This violates the requirement for clear examples of expected input and produces avoidable user confusion.

- **FAIL — Semantic and accessible form labelling**
  - Labels are rendered as separate sibling elements without `for` attributes, while inputs have no matching `id`.
  - For example, `E("label",{text:"Email"})` is not associated with the adjacent email input.
  - Screen readers and other assistive technologies may not identify the inputs correctly. This does not fully satisfy the semantic HTML and inclusive UX requirements.

- **PASS — Dyslexia-oriented UX features**
  - The UI uses plain wording, generous spacing, clear heading hierarchy, persistent help text, large controls, short instructions, no animated/flashing UI, and prominent primary actions.
  - It supports reveal/hide and re-request flows without penalty.
  - Browser autofill attributes are used for email, password, and one-time-code inputs.

- **PASS — Server-side authorization and IDOR resistance**
  - MFA endpoints use `auth()` or `csrf()`, which validate an HttpOnly session and ensure `session.userId === account.id`.
  - No user-controlled account identifier is accepted by MFA endpoints, preventing guessed-ID manipulation in this single-account mock.

- **PASS — CSRF protection**
  - State-changing endpoints require a trusted `Origin` and an `X-CSRF-Token` matching the server-side session token.
  - Session cookies use `SameSite=Strict`.

- **PASS — Secure headers, TLS, CORS, and cookies**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, and `Cache-Control: no-store` are set.
  - CORS is limited to explicit localhost TLS origins.
  - Session cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - The server is configured as TLS-only.

- **PASS — Secret storage and cryptographic handling**
  - Authenticator secrets are generated with `crypto.getRandomValues` and encrypted using AES-GCM before being retained in account state.
  - Recovery codes are generated using cryptographic randomness and stored as PBKDF2 hashes with unique salts.
  - Browser storage APIs and non-HttpOnly cookies are not used for secrets or sessions.

- **PASS — Input validation and XSS/injection defenses**
  - Inputs are type-checked, length-limited, and format-validated server-side.
  - The application has no SQL/database queries requiring prepared statements.
  - Client rendering uses `textContent` rather than unsafe `innerHTML`, mitigating reflected and DOM XSS.
  - No user-controlled redirect destination exists.

- **PASS — OTP/recovery-code expiry, single use, and rate limiting**
  - Identity codes expire and are invalidated after success or reissue.
  - TOTP validation is server-side, time-bound, and prevents reuse of an accepted time slot.
  - Recovery codes are marked used after successful use.
  - Identity, TOTP, and recovery-code failures have lockout behavior after repeated attempts.

- **PASS — Browser-console testing mocks**
  - The browser logs identity test codes, authenticator setup secrets/current OTPs, and recovery codes as requested for testing.
  - The values are returned to the UI where required for the simulated enrolment process.

## FAILING_ITEMS

- The displayed QR image is not an actual QR code and does not encode the provisioning URI. It cannot be scanned by a real authenticator app.
- The recovery-code example and placeholder, `ABCDE-FGHIJ`, are invalid because `I` is not allowed by the configured recovery-code character set.
- Form labels are not associated with their corresponding input controls through `for`/`id` relationships or label wrapping, reducing accessibility and semantic correctness.

## NEW_TASKS

1. Replace the custom `qr()` canvas pattern generator with an in-browser, standards-compliant QR-code encoder that encodes `provision.uri` and produces a QR image scannable by authenticator applications. Keep it self-contained in `app.ts` with no external assets or network calls.
2. Replace every recovery-code example and placeholder containing `ABCDE-FGHIJ` with a value accepted by `RECOVERY_CHARSET`, such as `ABCDE-FGHJK`.
3. Add unique `id` values to every input and matching `for` attributes to each corresponding `<label>`; alternatively, wrap each input inside its label while retaining the current visual layout.

## DECISION

FAIL