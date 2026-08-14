## SUMMARY

The artifact does not constitute a runnable single-file Bun application. The provided `app.ts` is truncated inside an unfinished route declaration (`if (path === "/api`), causing a TypeScript syntax error. As a result, the server cannot start, no HTML SPA is served, and the MFA flow cannot be tested end-to-end. While the visible server portion includes several positive security measures, the delivery fails the core functional, UX, and single-file runnable requirements.

## FUNCTIONAL_CHECK

- **Single `app.ts` file contains Bun server, HTML template, inline CSS, and browser-side JavaScript** — **FAIL**  
  The visible artifact contains server-side TypeScript only. It does not include an HTML document/template, inline CSS, or browser JavaScript UI. It also ends abruptly and is syntactically incomplete.

- **Bun serves a responsive mobile SPA directly, with no bundler/compiler/external assets** — **FAIL**  
  No route serving the SPA, HTML, CSS, or client-side JavaScript is present in the supplied artifact. Therefore responsive mobile rendering and direct browser interactivity are unavailable.

- **Bun server uses TLS certificates from `certs/cert.pem` and `certs/key.pem`** — **FAIL**  
  The code reads the certificate and key, but no visible `serve(...)` invocation configures TLS with them. Because the file is truncated, there is no evidence that HTTPS is actually enabled.

- **Sign-in and identity verification flow works** — **FAIL**  
  Server-side endpoints for bootstrap, sign-in, identity-code request, and identity verification are partially implemented, but there is no client UI to invoke them. The complete server routing and startup code are also missing due to truncation.

- **Authenticator provisioning, QR option, manual-secret entry, and verification work** — **FAIL**  
  The `/api/provision` endpoint returns a provisioning URI and secret, and verification logic is partially present. However, no client UI renders a QR code, displays/copies the secret, accepts manual setup, or submits the verification code. The stated requirement that offered QR/provisioning options permit manual submission is not demonstrated.

- **Backup recovery codes are displayed, can be securely stored by the user, and can be used for recovery** — **FAIL**  
  Backup codes are generated and returned following authenticator verification, and are PBKDF2-hashed at rest. However, the artifact is truncated before any recovery-code verification route or UI is shown. There is no visible recovery flow, copy/download/print interaction, or confirmation screen.

- **Mocks are deterministic and exposed through browser `console.log` for testing** — **FAIL**  
  Deterministic mock values are defined server-side and returned in API responses, but there is no browser-side JavaScript shown that logs the identity OTP, authenticator OTP, or recovery codes with `console.log`. The requirements specifically require mocks to be logged in the browser.

- **Inclusive dyslexia-friendly mobile UX is implemented** — **FAIL**  
  No HTML or CSS is present. Consequently, there is no evidence of a dyslexia-friendly typeface, spacing, plain-language content, icons, input examples, help, predictable stepper, primary-action hierarchy, no-motion design, retry/re-request controls, or accessible mobile layout.

- **Copy-to-clipboard, browser autofill/password-manager support, and reduced manual transcription are implemented** — **FAIL**  
  No browser UI or JavaScript is present, so copy controls, `autocomplete` attributes, input modes, QR presentation, and related usability features cannot be verified.

- **Every MFA endpoint enforces session ownership and prevents IDOR** — **PARTIAL / FAIL**  
  Visible MFA routes derive the account from the authenticated session rather than accepting a user ID, which is good. However, the app cannot run, and the server is truncated before all endpoints can be inspected. Therefore compliance for *every* endpoint cannot be accepted.

- **CSRF protection applies to all state-changing requests** — **PARTIAL / FAIL**  
  The visible authenticated POST routes enforce a per-session CSRF token; sign-in uses a one-time bootstrap ticket. This is a sound pattern. However, because the file is incomplete, later state-changing endpoints cannot be verified, and the artifact is non-runnable.

- **Secure response headers and restrictive CORS are configured** — **PARTIAL / FAIL**  
  The visible helper sets CSP, HSTS, `X-Content-Type-Options`, `X-Frame-Options`, no-cache directives, and restrictive localhost CORS. However, actual server startup, all response paths, TLS enforcement, and error handling are not available in the truncated artifact.

- **Session cookie is `HttpOnly`, `Secure`, and `SameSite` protected; sessions expire and are invalidated** — **PARTIAL / FAIL**  
  The cookie helper includes `HttpOnly`, `Secure`, and `SameSite=Strict`; idle and absolute session expiry are implemented in `auth()`. However, no completed logout endpoint is visible, despite the requirement to invalidate sessions on logout. The incomplete application cannot be accepted.

- **Secrets and backup codes are cryptographically protected at rest and securely generated** — **PARTIAL / FAIL**  
  OTP secrets are AES-GCM encrypted in memory, recovery codes are PBKDF2-hashed with random salts, and session/CSRF tokens use CSPRNG. However, the claimed practice OTP secret and recovery codes are deterministic constants, which does not meet the general requirement to generate OTP shared secrets and backup codes with cryptographically secure randomness. Deterministic values may be appropriate for mock verification, but they should not be persisted as the actual enrolment secret/codes if strict security requirements are being evaluated.

- **OTPs/recovery codes/session tokens are not exposed in logs, URLs, errors, or browser storage** — **FAIL**  
  The requirements explicitly require mock OTPs and recovery codes to appear in the browser console for testing, creating an intentional testing exception. However, the server API also returns secrets, mock OTPs, and backup codes in response bodies. No UI is present to limit when these are displayed or ensure they are only logged by browser-side mock logic. No evidence addresses browser storage because no client code exists.

- **Server input validation and output encoding prevent injection/XSS** — **PARTIAL / FAIL**  
  The visible JSON field validation and OTP/recovery-code validation are positive. There is no database usage, thus no SQL query issue is visible. But no HTML rendering/client DOM code is provided, so contextual output encoding and DOM-XSS safety cannot be verified.

- **Verification codes are time-bound, single-use, and rate-limited/locked after repeated failures** — **PARTIAL / FAIL**  
  Identity OTPs use expiry, single-use tracking, and a five-attempt lock. Authenticator setup uses a fixed code and an expiry in server state, but the API text says it “does not expire in this mock,” conflicting with the actual expiry and requirement for time-bound codes. Recovery verification is not present in the supplied code, so recovery-code rate limiting and single-use use cannot be verified.

- **No user enumeration and no open redirects** — **PARTIAL / FAIL**  
  Sign-in returns a generic error for invalid credentials, which helps prevent enumeration. No redirect functionality is visible. Since the artifact is incomplete, this cannot be accepted globally.

## FAILING_ITEMS

- `app.ts` is syntactically incomplete and ends in an unfinished statement: `if (path === "/api`.
- There is no visible `serve(...)` call, no completed request handler, and no evidence the Bun server starts.
- TLS certificate/key contents are loaded but not shown as used in a Bun TLS server configuration.
- No HTML document, semantic UI structure, inline CSS, or browser-side vanilla JavaScript is included.
- No responsive, mobile-legible, dyslexia-friendly UI is implemented or testable.
- No browser `console.log` implementation exists for deterministic mock identity codes, authenticator codes, or recovery codes.
- No QR-code rendering implementation is present.
- No copy-to-clipboard implementation is present.
- No browser autofill/password-manager-oriented form attributes are present.
- No visible route/UI for backup-code recovery, regeneration, storage guidance, or recovery-code verification.
- No visible logout endpoint/session invalidation implementation.
- Compliance cannot be verified for all endpoints because routing is cut off.
- The actual enrolment secret and recovery codes are fixed constants rather than generated with CSPRNG, conflicting with the cryptographic-generation requirement.
- The authenticator setup response claims the fixed practice code does not expire, while the server assigns it `CODE_LIFE` expiry; this is inconsistent and confusing.
- The server returns OTP/secret/recovery values in API payloads. This may be permissible for an explicit mock UI flow, but must be tightly limited to the required browser-side testing display/logging behavior and not treated as normal production behavior.

## NEW_TASKS

1. Complete and validate `app.ts` so it has valid TypeScript syntax, a complete API router, generic error handling, and a `Bun.serve` startup call.
2. Configure `Bun.serve` with `certs/cert.pem` and `certs/key.pem`, bind an appropriate localhost port, and serve the app only over HTTPS.
3. Add a complete HTML SPA response in `app.ts`, including semantic landmarks, inline CSS, and inline vanilla browser JavaScript compatible with the CSP nonce.
4. Implement the complete client flow: sign-in, identity-code request/re-request/verify, authenticator provisioning, code verification, backup-code display/confirmation, settings, recovery-code verification, recovery-code regeneration, and logout.
5. Implement responsive dyslexia-friendly mobile UI: legible font stack, adequate line/letter spacing, short plain-language instructions, examples, step indication, help text, one primary action per screen, no animation, and clear actionable errors.
6. Add accessible QR-code rendering for the provisioning URI and a manual secret option; include copy-to-clipboard controls for the secret, provisioning URI where useful, and recovery codes.
7. Add suitable form semantics and attributes, including labels, `autocomplete`, `inputmode="numeric"`, OTP autocomplete support where appropriate, and accessible status/error announcements.
8. In browser JavaScript, log deterministic mock identity/authenticator/recovery values to `console.log` only when the relevant mock action returns them; do not use browser storage for secrets, tokens, or codes.
9. Complete the server-side recovery-code verification and regeneration routes with session ownership checks, CSRF validation, input validation, one-time code consumption, rate limiting, and lockouts.
10. Add a logout endpoint that requires CSRF protection, deletes the active server session, and expires the session cookie.
11. Ensure every API route, including all later routes added to finish the file, consistently applies authorization, trusted-origin checks, CSRF checks for mutations, security headers, no-cache policy, and generic safe errors.
12. Replace static persisted enrolment secrets and backup codes with CSPRNG-generated values. If deterministic mock values are retained for academic testing, isolate them explicitly as non-persisted test-only verification values and make their expiry behavior consistent with server messages.
13. Test all internal navigation/actions end-to-end over HTTPS at a mobile viewport, including retries, re-requesting codes, failed-attempt locks, session expiry, logout, copy buttons, and recovery-code single use.

## DECISION

**FAIL**