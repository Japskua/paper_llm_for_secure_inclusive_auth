## SUMMARY

The artifact is a single-file Bun MFA enrolment application with a strong overall security structure: TLS, secure cookies, CSP/HSTS, server-side session ownership checks, CSRF validation, encrypted OTP secret storage, hashed recovery codes, input validation, and verification rate limiting are largely implemented correctly. The mobile UI is generally clear and accessible. However, it has functional and security-compliance defects that prevent acceptance: the displayed “QR” is not a scannable QR code, the initial test provisioning secret cannot be manually submitted because it fails server validation, authentication handling has observable timing differences, and backup codes are presented as single-use but there is no endpoint that consumes them.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no framework, bundler, compiler, or external assets**
  - The server, HTML, CSS, and browser JavaScript are all contained in `app.ts`.
  - It uses `Bun.serve` directly and does not import front-end frameworks or external assets.

- **PASS — TLS is configured with the required certificate paths**
  - `Bun.serve` loads `certs/cert.pem` and `certs/key.pem`.
  - The application serves over HTTPS and rejects non-HTTPS request URLs.

- **PASS — Mobile-responsive, readable enrolment UI**
  - The layout is constrained to a mobile-friendly maximum width, has large inputs/buttons, generous spacing, plain wording, icons, and predictable five-step navigation.
  - Inputs use relevant autocomplete attributes such as `email`, `current-password`, and `one-time-code`.

- **PASS — Identity-code verification works and supports resend/retry**
  - Identity OTPs are hashed, time-bound, single-use, and limited to five attempts before lockout.
  - Resend is supported with a resend window/rate limit.
  - Test-mode values are returned to the browser and written to the browser console/log view.

- **FAIL — Authenticator setup provides a functional QR-code option**
  - `drawQr()` creates a deterministic random-looking 29×29 black/white pattern, not a standards-compliant QR encoding of the `otpauth://` URI.
  - It cannot be scanned by an authenticator application, despite the UI telling the user to scan it.
  - The comment explicitly calls it a “QR-style visual option,” confirming it is not an actual QR code.

- **FAIL — Manual authenticator-secret submission works for all offered test values**
  - The first `TEST_SECRETS` value, `JBSWY3DPEHPK3PXPJBSWY`, contains 21 Base32 characters.
  - `/api/provision/manual` accepts only exactly 20 characters via `/^[A-Z2-7]{20}$/`.
  - Therefore, the normal first test-mode provisioning flow fails when the user presses “I added it to my app,” unless they first request a replacement setup secret.

- **PASS — Manual secret, copy-to-clipboard, hide/reveal, and setup-secret replacement are available**
  - The secret and provisioning URI can be copied.
  - The secret can be shown/hidden.
  - The user can paste the secret into an authenticator app and can request a replacement setup secret.

- **PASS — Authenticator verification is simulated in test mode and implemented as TOTP in normal mode**
  - Test mode accepts deterministic OTP `654321`.
  - Normal mode derives HMAC-SHA-1 TOTP values from the encrypted server-side secret.
  - OTP reuse is blocked and failed OTP attempts are rate-limited/locked.

- **PASS — Backup codes are generated securely, displayed, copied, hidden, and checked without accidental consumption**
  - Non-test recovery codes use cryptographically secure random generation.
  - Codes are stored as PBKDF2 hashes with per-code salts.
  - The confirmation screen explicitly verifies that the user saved a code without consuming it, which is appropriate for the enrolment confirmation action.

- **FAIL — Backup codes are actually enforceable as single-use recovery credentials**
  - The UI says each backup code “works once,” but there is no recovery-code-use endpoint or other code path that consumes/removes a matching code.
  - `/api/recovery/confirm` deliberately does not consume the code, and no endpoint exists to enforce one-time recovery-code use.
  - This does not satisfy the stated single-use verification-code expectation for the recovery credentials the app issues.

- **PASS — Server-side authorization and IDOR resistance**
  - Protected MFA endpoints retrieve the session from the HttpOnly cookie and verify the fixed authenticated account owner server-side.
  - Request bodies reject `userId` and `accountId`, and the application does not trust client-supplied account identifiers.

- **PASS — CSRF protections apply to state-changing authenticated operations**
  - State-changing POST requests require a session-bound CSRF token.
  - Session cookies use `SameSite=Strict`; cookies also use `HttpOnly`, `Secure`, and `Path=/`.

- **PASS — Secure HTTP response configuration**
  - Responses include CSP with nonces, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, no-store caching, and restrictive permissions/referrer policies.
  - CORS only returns credentialed CORS headers for configured local HTTPS origins.

- **PASS — Secrets are not persisted in browser storage**
  - There is no use of `localStorage`, `sessionStorage`, or client-readable cookies for OTP secrets, recovery codes, or session identifiers.
  - Production browser logs redact private values; test-only values are exposed only after a server-provided test-mode marker.

- **FAIL — Authentication response timing avoids user/account enumeration**
  - Login validation uses short-circuit logic:
    ```ts
    const valid = validInput &&
      constantEqual(email, DEMO_ACCOUNT.email) &&
      constantEqual(password, DEMO_ACCOUNT.password);
    ```
  - Malformed emails skip both comparisons, and valid-but-unknown emails skip the password comparison. This produces different processing paths/timing based on submitted identity data.
  - Although user-facing messages are appropriately generic, the implementation does not meet the requirement to avoid enumeration through response timing.

- **PASS — Input validation, output encoding, redirect handling, and generic server failures**
  - JSON request bodies are size-limited and reject identifier/redirect fields.
  - OTP, email, secret, and recovery-code formats are validated server-side.
  - Dynamic values rendered into HTML are escaped through `esc()`.
  - No redirect parameter is accepted; the only redirect is a server-generated HTTPS redirect.
  - Top-level failures return generic messages without stack traces.

## FAILING_ITEMS

- The authenticator “QR” display is not a valid, scannable QR code containing the provisioning URI.
- The default first test-mode provisioning secret is 21 characters, while the manual setup endpoint only accepts 20-character secrets. This breaks the primary manual setup path in test mode.
- Recovery codes are described as one-time credentials but are never consumable or invalidated because no recovery-code-use endpoint exists.
- Login authentication follows different code paths for malformed, unknown, and known email inputs, creating avoidable response-timing differences contrary to the anti-enumeration requirement.

## NEW_TASKS

1. Replace the `drawQr()` pseudo-random pattern generator with an in-file, standards-compliant QR encoder that encodes the generated `otpauth://` provisioning URI and produces a QR code scannable by authenticator applications.

2. Make test provisioning secrets conform to the same accepted Base32 format as production secrets, or adjust validation to safely accept the exact generated secret lengths. Ensure the initially supplied test secret can be pasted and accepted by `/api/provision/manual`.

3. Add a server-side recovery-code verification/use endpoint that requires the authenticated owner and CSRF token, checks hashes in constant-time style, atomically removes or marks the matching code used, and rejects future reuse. Keep `/api/recovery/confirm` non-consuming for the enrolment save-check flow.

4. Refactor sign-in credential validation so all login attempts perform equivalent credential-comparison work regardless of email format or account match, while retaining the same generic failure message and rate-limit behavior.

## DECISION

FAIL