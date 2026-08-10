## SUMMARY

The artifact is a valid single-file Bun HTTPS SPA with strong coverage of authentication, session ownership, CSRF, secure headers, encrypted OTP-secret storage, hashed recovery-code storage, mobile-friendly UX, and deterministic browser-side mock logging. However, it does not provide an actual QR-code option despite explicitly claiming one, and it generates recovery codes without implementing a route or UI flow to validate and consume them as one-time recovery codes. Therefore, not all functional and acceptance requirements are met.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no build tooling or external assets.**  
  The entire server, HTML template, CSS, and browser JavaScript are contained in `app.ts`. It uses Bun directly and only Node built-in cryptography imports.

- **PASS — HTTPS/TLS server uses the required certificate paths.**  
  `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`, and the server is intended to run at `https://localhost:3000`.

- **PASS — Responsive, mobile-oriented, dyslexia-conscious UI.**  
  The UI has a constrained mobile layout, large input/button controls, generous spacing, readable font fallbacks, plain language, visible current-step progress, icons, examples, retry actions, and no animated/timed reading UX.

- **PASS — Sign-in, identity verification, authenticator provisioning, and authenticator verification work through deterministic mocks.**  
  The identity code is deterministically `246810`; the current TOTP test code is calculated and returned to the browser. Both are logged in the browser console and the visible simulation-log area. Identity challenges are single-use and expire; TOTP validation includes replay protection.

- **PASS — Manual authenticator-secret and provisioning-link support is present.**  
  The setup screen provides a revealable manual secret and copy controls for both the secret and `otpauth://` provisioning URI.

- **FAIL — A QR-code option is not actually provided.**  
  The UI says an authenticator app “can scan a QR code,” but no QR image, SVG, canvas QR code, or other scannable QR representation is rendered. The requirement explicitly requires QR-code options in addition to copy-to-clipboard support.

- **PASS — Copy-to-clipboard support is implemented.**  
  The app offers clipboard actions for the authenticator secret, setup URI, and recovery-code list, with fallback messaging when clipboard access is unavailable.

- **PASS — Backup recovery codes are securely generated and displayed/saved.**  
  Eight recovery codes are generated using `randomBytes`, returned over the authenticated HTTPS session, displayed only after user action, copyable, printable, regenerable, and browser-console logged as required by the mock/testing requirement.

- **FAIL — Recovery codes cannot be verified or consumed.**  
  Although recovery-code verifiers are stored and a `recoveryMatches()` function exists, no API endpoint uses it. There is no recovery-code verification UI or server route, and used recovery codes are never removed. The UI claims that “Each code works once,” but this behavior is not implemented.

- **PASS — Server-side authorization and IDOR protections are correctly structured.**  
  MFA routes derive the account exclusively from the authenticated `mfa_session`; requests do not accept an account ID or user ID. Session-account ownership is checked on every authenticated route.

- **PASS — CSRF protections are applied to state-changing operations.**  
  Login uses a dedicated login CSRF token and strict cookie check. Authenticated state-changing endpoints require same-origin requests and the per-session `X-CSRF-Token`.

- **PASS — Secure session-cookie handling is present.**  
  Session cookies are `HttpOnly`, `Secure`, `SameSite=Strict`, path-scoped, expire after the absolute timeout, and are invalidated on logout. Session IDs are regenerated after successful authentication.

- **PASS — Secure headers and restrictive browser policy are configured.**  
  Responses include CSP with nonce-based scripts/styles, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, CSP `frame-ancestors 'none'`, no-referrer policy, permissions policy, and `Cache-Control: no-store`.

- **PASS — Sensitive server-side data handling is mostly appropriate.**  
  OTP secrets are AES-256-GCM encrypted in server memory; recovery codes are scrypt-hashed with per-code salts; session IDs and secrets are generated with cryptographic RNG. No secrets are stored in browser storage or URL query strings.

- **PASS — Input validation, generic error handling, and rate limiting are implemented.**  
  Email/password input is bounded, OTP and recovery-code formats are validated, server errors are generic, identity/TOTP failures are rate-limited and locked for ten minutes after repeated failures, and password authentication uses a dummy verifier to reduce account-enumeration/timing differences.

## FAILING_ITEMS

- **No QR code is rendered or offered.**  
  The provisioning screen only provides manual-secret and provisioning-URI copy controls. It does not create a scannable QR code despite the explicit QR-code requirement and its own text claiming QR scanning is possible.

- **Recovery-code verification is missing.**  
  `recoveryMatches()` and the stored recovery-code verifiers are unused. There is no authenticated endpoint accepting a recovery code, no UI for entering one, and no deletion/invalidating of an individual code after successful use.

- **The claim that recovery codes “work once” is currently false.**  
  Since recovery code submission does not exist, the application cannot demonstrate successful recovery-code use or enforce one-time consumption.

## NEW_TASKS

1. Implement a standards-compliant, scannable QR-code renderer for the `otpauth://` provisioning URI using only code embedded in `app.ts` (for example, generated inline SVG or canvas data), and add it to the authenticator provisioning screen alongside the existing manual-secret/copy options.

2. Add an authenticated, CSRF-protected `POST /api/recovery/verify` endpoint that validates a submitted recovery code against `account.recoveryVerifiers`, rate-limits failed attempts, and removes the matched verifier after successful use so that each code is single-use.

3. Add a mobile-friendly recovery-code entry screen or reachable recovery verification flow with a formatted example, `autocomplete` support where applicable, clear error messages, retry support, and a plain confirmation after a recovery code is accepted.

4. Update the recovery-code UI wording only after task 2 is complete so that the statement “Each code works once” accurately reflects enforced server behavior.

## DECISION

FAIL