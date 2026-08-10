## SUMMARY

The artifact is a valid single-file Bun/TypeScript SPA with responsive mobile UI, TLS configuration, server-side session checks, CSRF/origin protections, rate limits, encrypted authenticator-secret storage, Argon2id recovery-code hashing, and a functional enrolment flow under ideal timing. However, it does not fully meet the security and functional requirements: it logs the OTP shared secret in the browser, uses an overly permissive CSP, and validates the enrolment TOTP only for the exact provisioning time step rather than the current authenticator time step.

## FUNCTIONAL_CHECK

- **Single-file Bun server with inline HTML, CSS, and vanilla browser JavaScript: PASS**
  - The entire application, page template, client logic, and `Bun.serve` server configuration are contained in `app.ts`.
  - No framework, bundler, compilation pipeline, external asset, or external network call is used.

- **HTTPS/TLS using supplied mkcert certificate files: PASS**
  - `Bun.serve` uses `certs/cert.pem` and `certs/key.pem`.
  - No separate plain HTTP listener is configured.
  - HSTS is applied to responses.

- **Responsive, mobile-legible SPA UI: PASS**
  - The page uses a constrained mobile-width layout, viewport metadata, accessible form labels, readable typography, and a small-screen media query.
  - The enrolment screens transition within a single page without broken navigation.

- **Identity verification simulation works and exposes the mock code in browser console/UI logs: PASS**
  - `/api/signin` cryptographically generates a six-digit challenge.
  - The code is returned to the authenticated browser flow and logged with browser-side `console.log`.
  - Identity challenges are stored hashed, expire after five minutes, are invalidated after successful use, and are rate-limited.

- **Authenticator provisioning supports manual entry and simulated OTP verification: FAIL**
  - A manual Base32 secret and provisioning URI are returned, which satisfies manual setup support.
  - However, `/api/mfa/verify-enrollment` only accepts a TOTP calculated for the exact `timeStep` recorded when provisioning was created.
  - A legitimate authenticator app generates a new valid TOTP every 30 seconds. After the initial 30-second interval, a valid current TOTP from the displayed secret will be rejected even though the UI says the setup remains valid for five minutes.

- **Recovery codes are generated, displayed, logged in the browser, hashed at rest, single-use, and regenerable: PASS**
  - Eight recovery codes are generated with `crypto.getRandomValues`.
  - They are returned only to the authenticated UI, displayed once, and logged browser-side as required for the mock.
  - Server storage uses Argon2id hashes, and successful use removes the matching hash.
  - Regeneration replaces prior recovery-code hashes.

- **Server-side MFA authorization and IDOR prevention: PASS**
  - MFA endpoints derive account ownership exclusively from the server-side session.
  - No client-supplied account/user identifier is accepted by MFA routes.
  - Session `accountId` is checked against the authenticated account for protected routes.

- **CSRF protection for state-changing MFA actions: PASS**
  - Protected state-changing MFA endpoints require both the session CSRF token and an exact trusted `Origin`.
  - Cookies use `SameSite=Strict`.
  - Sign-in and identity verification additionally require a trusted origin; the pre-auth cookie is `SameSite=Strict`.

- **Security headers and CORS restriction: FAIL**
  - HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, referrer policy, and restricted CORS are present.
  - The CSP includes `script-src 'self' 'unsafe-inline'`. This permits arbitrary injected inline JavaScript and weakens CSP’s primary XSS mitigation. A nonce- or hash-based CSP is needed for the required inline script.

- **Cookie and session protections: PASS**
  - Session and pre-auth cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - Server-side idle and absolute session expiration are enforced.
  - Logout deletes the server-side session and clears the session cookie.
  - A fresh session identifier is generated after successful identity verification.

- **Sensitive-data logging protection: FAIL**
  - The browser client calls:
    - `logMock("Authenticator manual secret", r.manualSecret)`
  - This sends the OTP shared secret to the browser console and the visible Logs panel.
  - The requirements explicitly prohibit exposing OTP seeds in logs. The mock OTP and recovery codes may be logged as required, but the authenticator seed must not be logged.

- **Sensitive data is not persisted in browser storage: PASS**
  - No `localStorage`, `sessionStorage`, IndexedDB, or non-HttpOnly browser cookie is used for OTP secrets, codes, or session tokens.
  - Client state is in temporary JavaScript memory only.

- **Cryptographically secure generation and protected server storage: PASS**
  - Tokens, identity OTPs, Base32 secrets, and recovery codes use `crypto.getRandomValues`.
  - The authenticator secret is encrypted with AES-GCM before server-side storage.
  - Recovery codes use Argon2id hashes.

- **Input validation, output encoding, and redirect safety: PASS**
  - Email, phone number, OTP, and recovery-code formats are validated server-side.
  - Browser UI rendering uses `textContent` and DOM node construction rather than unsafe HTML interpolation.
  - There are no user-controlled redirects or redirect parameters.

- **Generic errors and anti-enumeration behavior: PASS**
  - The server returns generic error messages rather than account-specific messages or stack traces.
  - Invalid sign-in credential paths use equivalent generic responses.
  - Server exceptions are caught and returned as generic 500 responses.

- **Rate limiting and lockouts: PASS**
  - Sign-in, identity verification, enrolment OTP verification, and recovery-code use have attempt limits and temporary lockouts.
  - Successful verification clears the relevant failure tracker.

## FAILING_ITEMS

- The browser logs the authenticator shared secret via `logMock("Authenticator manual secret", r.manualSecret)`. This violates the explicit requirement not to expose OTP seeds in logs.
- The CSP permits inline scripts through `script-src 'unsafe-inline'`, substantially weakening XSS protection despite the requirement for secure CSP headers.
- Enrolment TOTP validation is bound to the provisioning-time step (`provision.timeStep`) instead of the current TOTP step. Valid authenticator codes generated after the first 30 seconds are rejected, contradicting expected time-based authenticator behavior and the UI’s five-minute setup validity statement.

## NEW_TASKS

1. Remove browser-console and Logs-panel output of `manualSecret`; continue returning/displaying the secret only in the protected manual setup UI, and retain browser logging only for the required mock OTP and recovery codes.
2. Replace CSP `script-src 'self' 'unsafe-inline'` with a per-response cryptographic nonce or script hash; apply the nonce to the inline `<script>` tag. Remove unnecessary `'unsafe-inline'` permissions where feasible.
3. Update `/api/mfa/verify-enrollment` to validate the submitted TOTP against the current 30-second time step, optionally allowing a narrowly bounded clock-skew window such as current step ±1.
4. Update provisioning/mock behavior so the displayed simulated OTP corresponds to the current accepted TOTP step, and revise UI copy to accurately describe the valid code timing.

## DECISION

**FAIL**