## SUMMARY

The artifact is a well-structured single-file Bun application with a functional simulated MFA flow, secure session cookies, CSRF checks, ownership-bound server state, encrypted authenticator secrets, hashed recovery codes, security headers, and mobile-focused UI styling. However, it does not fully meet the requirements because it can start and serve insecure HTTP when TLS certificates are unavailable, the displayed “QR code” is not a scannable QR code, failed authenticator/recovery verification attempts are not rate-limited or locked out, and several required dyslexia-support interaction features are incomplete.

## FUNCTIONAL_CHECK

- **Single `app.ts` file containing Bun server, HTML, CSS, and vanilla browser JavaScript: PASS**
  - The server, inline HTML template, CSS, and client-side JavaScript are all present in one `app.ts` file.
  - No framework, build tool, bundler, compiler invocation, or external asset is used.

- **Bun server uses supplied TLS certificates: PARTIAL / FAIL**
  - The server correctly detects and configures `./certs/cert.pem` and `./certs/key.pem` when they exist.
  - However, when certificates are absent, it starts an HTTP server instead of refusing to start or otherwise enforcing HTTPS. This violates the explicit requirement to enforce HTTPS/TLS for all traffic.
  - The secure session cookie will also not function correctly over the HTTP fallback because it has the `Secure` attribute.

- **MFA enrolment flow works end-to-end: PASS**
  - Sign-in, identity-code request and verification, authenticator setup, authenticator verification, recovery-code generation, confirmation, recovery-code use, and logout are all implemented.
  - The server enforces step order through the session `stage`.
  - The identity OTP is time-bound and marked as used after successful verification.
  - Recovery codes are marked used after successful use.

- **Mocks are available in browser console and UI: PASS**
  - Identity verification codes, authenticator setup keys/codes, and recovery codes are returned to the authenticated UI and logged through browser-side `console.log`.
  - The server itself does not log these values.

- **Authenticator provisioning provides a real QR-code option: FAIL**
  - `drawQr()` generates pseudorandom block characters, not a valid QR code encoding the provisioning URI.
  - An authenticator application cannot scan this output.
  - The manually copyable secret is useful, but it does not make the claimed “scan this setup square” option functional.

- **Manual secret/code entry alternatives are available: PASS**
  - The authenticator secret is visibly displayed and can be copied.
  - The user can manually enter the six-digit authenticator code.
  - Identity and recovery-code inputs support manual entry with examples.

- **Server-side authorization and IDOR prevention: PASS**
  - MFA endpoints use `requireSession()` and derive the account exclusively from `session.userId`.
  - No client-supplied account/user identifier is accepted by MFA endpoints.
  - Requests with missing, expired, manipulated, or unauthenticated sessions are rejected.

- **CSRF protection for state-changing operations: PASS**
  - State-changing API routes require `X-CSRF-Token`.
  - The token is stored server-side in the session.
  - Same-origin validation is also applied to mutation routes.
  - Session cookies use `SameSite=Strict`.

- **Secure session management: PASS**
  - Session IDs are opaque, server-owned random values.
  - Sessions are rotated after sign-in.
  - Idle and absolute session expiry are implemented.
  - Logout invalidates the server session and clears the cookie.
  - Session cookies are configured as `HttpOnly`, `Secure`, and `SameSite=Strict`.

- **Secure headers and CORS restrictions: PASS**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, referrer policy, permissions policy, and no-store caching are set.
  - CORS only returns `Access-Control-Allow-Origin` for the server’s own origin.

- **Secrets protected at rest and generated securely: PASS**
  - Authenticator secrets are generated using `randomBytes()` and stored using AES-256-GCM encryption.
  - Recovery codes are generated using `randomBytes()` and stored only as peppered hashes.
  - Session and CSRF tokens use cryptographically secure random generation.

- **Input validation and injection defenses: PASS**
  - Email, phone, OTP, recovery-code, and request-body size validation are implemented.
  - The application does not use SQL or dynamically interpolate user input into HTML.
  - Client rendering of recovery codes uses `textContent`, avoiding DOM XSS.
  - No redirect parameter is implemented, so no open redirect is exposed.

- **Verification-code single-use, time limits, and brute-force resistance: FAIL**
  - Identity codes are time-bound, single-use, and have an attempt lockout.
  - Authenticator verification has no failed-attempt counter, rate limit, or lockout.
  - Recovery-code verification has no failed-attempt counter, rate limit, or lockout.
  - Re-requesting an identity code replaces the identity verification state and resets the failure count/lock state, allowing a user to bypass the intended identity-code lockout by repeatedly requesting new codes.
  - Sign-in attempts also have no rate limiting or lockout protection.

- **Dyslexia-inclusive mobile UX: PARTIAL / FAIL**
  - The UI has a responsive mobile layout, generous spacing, readable type sizing, plain-language instructions, examples, icons, focus styling, short step labels, and no moving/timed-reading UI.
  - However, the user cannot hide sensitive setup/recovery codes after viewing them, despite the requirement to let users reveal and hide codes.
  - The help screen’s “Go back” button always returns to sign-in because `show("help")` overwrites `current`; it does not return the user to the screen from which Help was opened.
  - The pseudo-QR display also undermines the low-transcription accessibility goal because the scan option cannot work.

- **Internal links and navigation function correctly: PARTIAL / FAIL**
  - Help and logout links are intercepted and generally work.
  - The Help “Go back” navigation is incorrect for any screen other than sign-in.

- **Generic production error handling: PASS**
  - The top-level server catch returns a generic error response without stack traces or sensitive information.

## FAILING_ITEMS

- The application starts an insecure HTTP server whenever TLS certificate files are unavailable. This violates the HTTPS/TLS-only requirement and causes the `Secure` session cookie to be unusable in the HTTP fallback.
- The “setup square” is not a valid QR code. `drawQr()` produces decorative random text rather than an encoding of the `otpauth://` provisioning URI.
- Authenticator OTP verification has unlimited failed attempts and no lockout/rate limiting.
- Recovery-code verification has unlimited failed attempts and no lockout/rate limiting.
- Identity verification lockout is bypassable because each `/api/identity/request` replaces the verification state, including its attempts and `lockedUntil` values.
- Sign-in has no throttling or lockout for repeated failed authentication attempts.
- The UI does not provide controls to hide/reveal the authenticator secret or recovery codes after they are displayed.
- The Help screen’s “Go back” action always returns to sign-in rather than the previously active step.

## NEW_TASKS

1. Require TLS certificates at startup and refuse to serve the application if `certs/cert.pem` or `certs/key.pem` is missing; remove the insecure HTTP fallback entirely.

2. Replace `drawQr()` with an in-browser, valid QR-code encoder that encodes the returned provisioning URI and renders a scannable QR code without external libraries or network calls.

3. Add server-side, session/account-bound failed-attempt tracking and lockout/rate limiting for authenticator OTP verification and recovery-code verification.

4. Make identity-code lockout survive code re-requests for the lockout duration, and rate-limit identity-code requests so repeated re-requesting cannot bypass brute-force protection.

5. Add throttling/lockout controls for repeated failed sign-in attempts using generic, non-enumerating error responses.

6. Add explicit “Hide” and “Show again” controls for the authenticator setup key and recovery-code list while retaining copy/download functionality.

7. Track the view active before opening Help and make the Help “Go back” button return to that prior view.

## DECISION

**FAIL**