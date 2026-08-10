## SUMMARY

The artifact is a single-file Bun HTTPS SPA with substantial security and UX work: server-side sessions, CSRF checks, secure cookie flags, CSP/HSTS headers, encrypted TOTP secret storage, hashed recovery codes, rate limiting, and a mobile-oriented UI are implemented. However, it does not fully meet the requirements because recovery-code replacement is broken, the displayed “QR” image is not a real scannable QR code, and the apparent account-owner authentication is publicly disclosed in the UI. The enrolled-account UI flow also dead-ends after a later sign-in.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with inline HTML, CSS, and vanilla browser JavaScript**
  - The application server, HTML template, CSS, and client JavaScript are all contained in `app.ts`.
  - There are no framework imports, bundlers, compilation steps, or external network assets.

- **PASS — HTTPS/TLS Bun server**
  - `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`.
  - The server is HTTPS-only and includes HSTS.

- **PASS — Mobile-responsive, readable SPA UI**
  - The layout has a constrained mobile-width shell, legible sizing, high line-height, visible form controls, generous spacing, and plain-language instructions.
  - Inputs include examples, mobile numeric keyboards where appropriate, `autocomplete="one-time-code"`, and password/email autocomplete attributes.

- **PASS — Simulated identity and authenticator verification work**
  - Identity codes are generated using `crypto.getRandomValues`, returned for the demo, and logged in the browser console.
  - TOTP verification uses HMAC-SHA-1 with a 30-second time step and accepts a bounded clock-skew window.
  - TOTP time steps are tracked in `acceptedSteps`, preventing reuse of an accepted TOTP step.

- **PASS — Recovery-code generation and single-use verification**
  - Recovery codes are generated using cryptographically secure random bytes.
  - Recovery codes are stored as peppered SHA-256 hashes rather than plaintext.
  - Successful recovery-code use removes the matching hash, making the code single-use.

- **FAIL — Recovery-code replacement does not function**
  - The route test uses `url.pathname.endsWith("generate")`.
  - `"/api/mfa/recovery/regenerate".endsWith("generate")` is `true`, so the regenerate request is incorrectly handled as a generate request.
  - Since recovery hashes already exist when replacing codes, the endpoint returns: “Recovery codes already exist. Use replacement only if you need a new set.”
  - Therefore the UI’s **“Yes, replace my codes”** action cannot complete.

- **FAIL — The displayed authenticator “QR picture” is not an actual QR code**
  - `drawQr(d.uri)` uses a pseudo-random canvas pattern seeded by the provisioning URI. It does not encode the `otpauth://` URI using the QR-code format.
  - An authenticator application cannot scan this canvas to provision the account.
  - The UI claims users can “Scan this QR picture with an authenticator app,” which is false.
  - The manual secret is available, but that does not make the offered QR option functional.

- **FAIL — Account-owner authentication is not meaningfully enforced**
  - The account credential is hard-coded as `Marcus-Access-54`.
  - The same credential is explicitly exposed to every visitor in the UI text and input placeholder: `Example: Marcus-Access-54`.
  - Any visitor who knows the fixed email can create an authenticated session for Marcus and access or modify MFA state.
  - This does not satisfy the requirement that only the authenticated account owner may view or modify their MFA settings.

- **FAIL — An already enrolled user cannot continue through the UI after a new sign-in**
  - After a later sign-in and identity verification, the client always opens the setup screen and calls `/api/mfa/provision`.
  - The server correctly rejects provisioning for an already enrolled account with HTTP 409.
  - The client then only displays an error, with no UI path to verify the existing authenticator, use a recovery code, view recovery-code status, or replace recovery codes.
  - This makes post-enrolment MFA management inaccessible through the supplied UI.

- **PASS — Server-side authorization and IDOR resistance for the modeled account**
  - MFA state is fetched from the authenticated session’s `userId`, not from a caller-supplied account identifier.
  - Requests with missing, expired, or mismatched sessions are rejected.
  - The API does not accept arbitrary user IDs in MFA endpoint payloads.

- **PASS — CSRF protection for authenticated state-changing MFA operations**
  - Authenticated POST endpoints require a session-bound `X-CSRF-Token`.
  - The session cookie has `HttpOnly`, `Secure`, and `SameSite=Strict` attributes.
  - Origin checks restrict browser cross-origin requests to configured localhost HTTPS origins.

- **PASS — Secure response headers and restricted CORS**
  - CSP includes nonce-based script/style policy, `connect-src 'self'`, and `frame-ancestors 'none'`.
  - HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, and no-store cache controls are set.
  - CORS is limited to configured trusted localhost origins.

- **PASS — Secrets are protected at rest and not persisted in browser storage**
  - TOTP secrets are AES-GCM encrypted before persistence.
  - Recovery codes are hashed before persistence.
  - No `localStorage`, `sessionStorage`, or non-HttpOnly cookie storage is used for secrets or session tokens.

- **PASS — Input validation, output encoding, and redirect safety**
  - JSON request bodies are size-limited and validated.
  - Email, credential, OTP, and recovery-code formats are checked server-side.
  - User-facing messages are escaped before insertion into `innerHTML`.
  - There are no redirect parameters or externally controlled redirects.

- **PASS — Rate limiting, lockout, expiry, and session lifecycle controls**
  - Failed owner, identity, TOTP, and recovery-code attempts are tracked and locked after five failures.
  - Identity codes expire after ten minutes and are invalidated after use or resend.
  - Sessions have idle and absolute expiration limits.
  - Session IDs are rotated after successful owner authentication.
  - A logout endpoint invalidates the server-side session and clears the cookie.

## FAILING_ITEMS

- Recovery-code regeneration is unreachable due to the incorrect `endsWith("generate")` route condition.
- The QR canvas is a decorative pseudo-random image, not a standards-compliant QR encoding of the provisioning URI.
- The only account credential is intentionally revealed to every user, allowing anyone to impersonate the modeled account owner.
- The client has no enrolled-account management path; an already enrolled account receives a provisioning conflict and cannot proceed to existing-authenticator or recovery-code actions.
- The UI presents a QR scan option as functional even though it cannot be scanned by authenticator applications.

## NEW_TASKS

1. Replace the recovery route suffix check with exact route matching so `/api/mfa/recovery/generate` and `/api/mfa/recovery/regenerate` execute separate logic; ensure regeneration replaces hashes and returns a newly generated code set.

2. Implement an actual QR-code encoder in the inline client JavaScript, or remove the QR scan claim and UI entirely. If retained, encode the returned `otpauth://` provisioning URI into a standards-compliant scannable QR code.

3. Replace the publicly disclosed hard-coded owner credential with a valid authentication model for the demo that does not reveal the account-owner credential to arbitrary visitors. Ensure MFA-management sessions can only be established after owner authentication.

4. Add an enrolled-account branch after identity verification. When MFA is already enrolled, provide a UI to verify the existing authenticator or a recovery code and then access recovery-code management, including replacement.

5. Update the authenticator setup wording and accessibility label only after the QR implementation is genuinely scannable; otherwise label it accurately as a non-scannable visual is not acceptable.

## DECISION

**FAIL**