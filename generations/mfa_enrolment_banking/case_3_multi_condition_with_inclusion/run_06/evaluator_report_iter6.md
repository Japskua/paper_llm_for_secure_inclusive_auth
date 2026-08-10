## SUMMARY

The artifact is a single `app.ts` Bun application with a responsive, generally accessible MFA flow and many strong security controls: TLS configuration, secure headers, HttpOnly/Secure/SameSite cookies, CSRF checks for protected POST routes, encrypted TOTP secret storage, hashed recovery codes, OTP expiry/single-use protections, session rotation, and lockout handling. However, it does not fully meet the requirements because the public “demo sign-in” endpoint grants a Marcus account session without authenticating the account owner, the displayed “QR code” is not a valid scannable QR code, and mock/test delivery values are not consistently deterministic or browser-logged as required.

## FUNCTIONAL_CHECK

- **PASS — Single-file application and no framework/build dependency**
  - The full server, HTML, CSS, and browser JavaScript are contained in `app.ts`.
  - It uses Bun directly and has no external assets, framework imports, bundler configuration, or network calls.

- **PASS — Bun HTTPS server uses supplied certificate paths**
  - `Bun.serve` is configured with:
    - `certs/cert.pem`
    - `certs/key.pem`
  - The server is intended to run over HTTPS and emits an HTTPS startup URL.

- **PASS — Responsive, mobile-oriented UI**
  - The app includes a mobile viewport tag and constrained responsive content width.
  - Inputs and buttons have large touch targets and readable sizing.
  - A mobile breakpoint is present for narrow displays.

- **PASS — Dyslexia-aware visual and interaction design**
  - The UI uses short sentences, examples for expected input, icons paired with headings, generous line height/letter spacing, and clear focus states.
  - It avoids moving/flashing elements and does not impose a reading timer.
  - It provides expandable help and retry/re-send actions.

- **PARTIAL / FAIL — QR-code option**
  - The UI presents an SVG labelled as an authenticator QR code.
  - However, `qr(uri)` creates a pseudo-random “QR-style” image rather than encoding the `otpauth://` URI according to the QR specification.
  - An authenticator app cannot reliably scan this image, so the required QR setup option is not functional.
  - The manual secret/copy alternative is implemented correctly.

- **PASS — Copy and manual-entry support**
  - The provisioning secret can be shown/hidden and copied.
  - Backup recovery codes can be shown/hidden and copied.
  - OTP fields use `autocomplete="one-time-code"` and suitable numeric input modes.

- **FAIL — Simulated deterministic mock values and browser-console delivery**
  - Outside `MFA_TEST_MODE`, identity codes are cryptographically random and are not returned to the UI or logged in the browser.
  - In test mode, the identity code and TOTP seed are fixed, but backup recovery codes remain randomly generated.
  - The requirements explicitly require deterministic mock values for simulated delivery/testing and require examples such as OTPs and backup codes to be returned to the UI and shown through browser `console.log`.
  - The current behavior only exposes these values conditionally and does not provide deterministic recovery-code fixtures.

- **PASS — MFA verification flow works in principle**
  - Identity verification is required before provisioning.
  - TOTP verification checks a valid six-digit code over a narrow time window.
  - Accepted TOTP counters cannot be reused.
  - Recovery codes are normalized, verified, and removed after successful use.

- **FAIL — Authenticated-account-owner enforcement**
  - `POST /api/demo/login` is publicly accessible and immediately creates a session for `ACCOUNT_ID` without validating credentials, an existing authenticated-bank session, or any proof that the caller is Marcus.
  - Any visitor can therefore obtain an authenticated session for Marcus and access or modify MFA settings.
  - Although protected MFA endpoints check `session.accountId === ACCOUNT_ID`, this does not protect the account because the public login endpoint assigns that account ID to every caller.
  - This fails the requirement that only the authenticated account owner may view or modify their own MFA settings.

- **PASS — CSRF protection for protected MFA state changes**
  - Protected POST endpoints require an owner session and a matching `X-CSRF-Token`.
  - The origin is checked against an allow-list.
  - CSRF tokens are stored server-side in session state and are rotated with the session after identity verification.

- **PASS — Session cookie and lifecycle controls**
  - The session cookie uses `HttpOnly`, `Secure`, `SameSite=Strict`, and `Path=/`.
  - Idle and absolute session timeouts are enforced server-side.
  - The session ID is rotated after identity verification.
  - Logout invalidates the session and expires the cookie.

- **PASS — Security response headers and CORS restriction**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, no-referrer policy, permissions policy, and no-store caching are configured.
  - CORS preflight responses are restricted to the configured trusted origins.
  - Normal application endpoints do not broadly enable cross-origin access.

- **PASS — Secret and recovery-code protection at rest**
  - TOTP secrets are encrypted using AES-256-GCM with a random IV.
  - Recovery codes are generated with `randomBytes` and stored as salted `scrypt` hashes.
  - Secrets, OTPs, and session IDs are not put in localStorage, sessionStorage, URLs, or client-readable cookies.

- **PASS — Input validation and XSS protections**
  - Phone suffixes, six-digit OTPs, and recovery-code formats are validated server-side.
  - Dynamic user-facing values are escaped in browser rendering through `esc`.
  - The server does not accept user-controlled redirect targets.

- **PASS — Rate limiting, lockout, expiry, and one-time verification**
  - Identity codes expire after 15 minutes and are marked used.
  - TOTP counters are not reusable.
  - Recovery codes are deleted after successful use.
  - Repeated failed attempts trigger a five-minute lockout after five failures.

- **PARTIAL / FAIL — Server-side flow-state enforcement for recovery**
  - `/api/recovery/verify` does not require `record.mfaEnabled`.
  - A session owner who has generated backup codes can call this endpoint before `/api/complete` and consume a recovery code before MFA setup is formally completed.
  - The UI normally prevents this, but server-side workflow state should also be enforced for a security-sensitive action.

- **PASS — Code validity**
  - The TypeScript and browser JavaScript appear syntactically valid.
  - No obvious unresolved identifiers or malformed Bun server configuration are present, assuming the required certificate files exist.

## FAILING_ITEMS

- The public `POST /api/demo/login` endpoint grants an authenticated Marcus session to any caller without authenticating the account owner.
- The academic test-login route also creates the Marcus session from a static client-entered phrase; it is only gated by `MFA_TEST_MODE`, but it should not be usable as a production authentication mechanism.
- The SVG produced by `qr(uri)` is not a real QR encoding of the provisioning URI and will not be reliably scannable by authenticator applications.
- Simulated test values are not consistently deterministic:
  - Recovery codes remain random in test mode.
  - Normal-mode identity delivery is random and not exposed for simulation/testing.
- OTP and recovery-code browser-console output is inconsistent with the stated mock/testing deliverable:
  - It is only performed for selected values in test mode.
  - There is no coherent, explicitly test-only deterministic fixture flow covering identity OTP, authenticator OTP, and recovery codes.
- `/api/recovery/verify` can be used after backup generation but before MFA completion because it does not require `record.mfaEnabled`.

## NEW_TASKS

1. Replace the public demo authentication mechanism with a real authenticated-session boundary: in production, require a trusted pre-authenticated bank session/server-side identity assertion before issuing an MFA session for `ACCOUNT_ID`; keep any fixture login available only under an explicit test-only configuration and never as the production authentication path.

2. Replace `qr(uri)` with a standards-compliant local QR-code encoder that encodes the generated `otpauth://` provisioning URI into a scannable SVG or canvas image, without adding external network dependencies.

3. Define a coherent explicit academic test mode in which the identity OTP, authenticator seed/current OTP behavior, and recovery-code fixture values are deterministic, returned to the browser UI as needed, and logged using browser `console.log`; preserve cryptographically secure random generation and avoid secret logging in non-test mode.

4. Add server-side state validation to `/api/recovery/verify` so recovery verification is rejected unless MFA setup has been completed (`record.mfaEnabled === true`), with a clear user-safe error message.

## DECISION

FAIL