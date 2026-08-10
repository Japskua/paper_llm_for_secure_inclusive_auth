## SUMMARY

The artifact is a single-file Bun application with inline HTML, CSS, and vanilla browser JavaScript. It implements a functional MFA enrolment flow, HTTPS/TLS, session cookies, CSP/security headers, CSRF tokens for authenticated mutations, encrypted OTP-secret persistence, hashed recovery codes, OTP expiry/single-use controls, and mobile-oriented accessible wording. However, it has security and UX defects that prevent acceptance: sign-in is vulnerable to account enumeration, the session-creating sign-in request lacks effective CSRF/origin enforcement, and the authenticator setup UI has a race condition that can fail if the demo-code action is used before provisioning completes. The already-enrolled recovery-code path is also misleading and leads to an avoidable error.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun implementation**
  - The supplied artifact is one `app.ts` file containing the Bun server, HTML template, inline CSS, and inline vanilla JavaScript. No framework, bundler, compiler, or external asset is used.

- **PASS — TLS / HTTPS serving**
  - `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`.
  - Secure cookies and HSTS are configured, so the design is intended to operate over HTTPS.

- **PASS — Mobile SPA and inclusive presentation**
  - The page includes a mobile viewport meta tag, constrained mobile-width layout, readable font sizing, adequate line spacing, clear labels, visible step indicators, short instructions, input examples, help sections, and prominent primary actions.
  - The UI avoids animation, flashing, and reading timers.

- **PASS — MFA enrolment flow functionality**
  - The flow covers sign-in, owner approval, identity verification, authenticator provisioning, TOTP verification, recovery-code generation, recovery-code use, code hiding/revealing, copying, and regeneration.
  - Internal flow navigation is implemented in the SPA rather than through broken or placeholder links.

- **PASS — Browser-console demo values**
  - Owner approval codes, identity codes, revealed demo authenticator codes, and generated/replacement recovery codes are logged with `console.log` in browser-side JavaScript.
  - Codes are returned to the client only for the stated simulated/test flow.

- **PASS — Manual authenticator setup alternative**
  - The authenticator setup screen provides a QR code and a readable setup key with a copy button, allowing the secret to be manually entered into an authenticator application.

- **PASS — Secure response headers and cookie attributes**
  - CSP includes nonce-based inline script/style authorization and `frame-ancestors 'none'`.
  - HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, and `Cache-Control: no-store` are set.
  - Session cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`.

- **PASS — Server-side MFA authorization and IDOR resistance**
  - MFA routes require an authenticated server-side session and verify `s.userId === USER.id`.
  - No client-provided account/user identifier is accepted by MFA endpoints, so guessed or manipulated IDs cannot select another account.

- **PASS — CSRF token protection for authenticated MFA state changes**
  - Authenticated POST endpoints require `X-CSRF-Token` matching the server-held session token.
  - This protects MFA provisioning, verification, recovery-code generation/regeneration, and logout after a session exists.

- **FAIL — Effective CSRF protection for all state-changing requests**
  - `/api/auth/signin` creates and sets a new authenticated-session cookie but does not require a CSRF token or a trusted `Origin`.
  - `originOK()` explicitly accepts requests with no `Origin` header (`o === null`), including the session-creating endpoint. The requirement calls for CSRF protection on state-changing requests; session creation should be protected by strict Origin/Referer validation or an equivalent bootstrap mechanism.

- **FAIL — Account/user enumeration resistance**
  - `/api/auth/signin` returns `200` and a session cookie only when the submitted email is exactly `marcus@example.test`; all other syntactically valid addresses return `401`.
  - This makes account existence directly observable through HTTP status, response behavior, and likely timing, violating the requirement to avoid user/account enumeration in messages and response timing.

- **PASS — OTP and recovery-code security controls**
  - Owner and identity challenges are six digits, generated with `crypto.getRandomValues`, time-bound for ten minutes, and marked single-use.
  - TOTP values are accepted only once per relevant time step through `acceptedSteps`.
  - Recovery codes are removed after successful use.
  - Failed verification attempts are tracked and lock for 15 minutes after five failures.

- **PASS — Session security controls**
  - Session IDs are cryptographically generated.
  - A new session is issued at sign-in and again after owner verification.
  - Idle and absolute timeouts are enforced server-side.
  - Logout invalidates the server session and expires the cookie.

- **PASS — Encryption/hashing at rest**
  - OTP seeds are AES-GCM encrypted before persistence.
  - Recovery codes are persisted as peppered SHA-256 digests rather than plaintext.
  - Production startup requires configured master-key and pepper values.

- **PASS — Input validation and output encoding**
  - JSON request size/type is restricted.
  - Email, six-digit OTP, and recovery-code formats are validated server-side.
  - User-visible dynamic text in the browser is escaped before use in `innerHTML`.
  - The application does not use SQL, redirects, or external URLs requiring database-query or open-redirect controls.

- **FAIL — Authenticator setup action can fail before provisioning is ready**
  - The setup screen renders the “Reveal demo authenticator code” button immediately, while `/api/mfa/provision` runs asynchronously.
  - If the user presses that button before `secret` is assigned, `clientTotp(secret)` receives an empty secret and can reject during `crypto.subtle.importKey`.
  - This produces an unhandled failure rather than a clear, actionable message or a disabled control.

- **FAIL — Existing-account recovery-code management leads to a misleading error**
  - After an existing enrolled user verifies their authenticator, `existing()` sends them to `recoveryPage()`.
  - That page says “Save recovery codes” and presents “Show recovery codes,” but `/api/mfa/recovery/generate` correctly rejects because recovery codes already exist and cannot be recovered in plaintext.
  - This produces an unnecessary `409` error and does not provide a clear existing-code management screen. The UI should explain that existing codes cannot be shown again and offer replacement only after confirmation.

## FAILING_ITEMS

- The session-creating `/api/auth/signin` endpoint is state-changing but does not enforce a trusted `Origin`/`Referer` or equivalent CSRF bootstrap protection. `originOK()` accepts a missing `Origin`.
- The sign-in endpoint exposes whether `marcus@example.test` exists through different status codes and success behavior, enabling account enumeration.
- The setup screen permits use of “Reveal demo authenticator code” before the asynchronous provisioning response supplies the secret, causing an unhandled browser-side cryptographic error.
- The post-verification experience for an already-enrolled account incorrectly presents recovery-code generation as though existing recovery codes can be shown again, then returns an avoidable error.

## NEW_TASKS

1. Require a trusted same-origin `Origin` header for all browser POST requests, including `/api/auth/signin`; reject missing or untrusted origins for session-creating and state-changing requests. Keep CSRF-token validation for requests after session creation.

2. Change sign-in behavior to avoid observable account enumeration:
   - Return the same generic response/status/message for syntactically valid email submissions.
   - Make the mock sign-in/owner-challenge path behavior and timing materially equivalent for known and unknown addresses, without disclosing account existence.

3. Update authenticator setup loading behavior:
   - Disable the setup-key copy and demo-code controls until `/api/mfa/provision` succeeds and supplies the secret.
   - Display a clear loading/status message.
   - Catch and present any demo-code generation failure as an actionable UI error rather than allowing an unhandled rejection.

4. Add a distinct recovery-code management view for already-enrolled users after successful TOTP/recovery verification:
   - Explain that previously generated plaintext recovery codes cannot be displayed again.
   - Offer only replacement/regeneration with explicit confirmation.
   - Reserve the “Show recovery codes” generation screen for the initial enrolment case where no recovery-code hashes exist.

## DECISION

FAIL