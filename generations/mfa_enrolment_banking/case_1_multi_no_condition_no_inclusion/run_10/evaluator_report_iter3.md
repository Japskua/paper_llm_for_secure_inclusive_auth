## SUMMARY

The artifact is a valid single-file Bun HTTPS SPA with substantial security controls: server-side session checks, CSRF tokens, secure cookies, TLS configuration, CSP/HSTS headers, encrypted authenticator secrets, hashed recovery codes, generic errors, and functional mocked identity/TOTP flows. However, it does not fully meet the requirements because many generated recovery codes cannot be verified due to a validation-regex mismatch, email/phone validation is insufficient, and the session ID is not rotated after successful authentication.

## FUNCTIONAL_CHECK

- **Single-file Bun server with inline HTML, CSS, and vanilla JavaScript — PASS**
  - The application is contained in `app.ts`.
  - It uses `Bun.serve`, returns a complete HTML document, and contains inline CSS and browser-side JavaScript.
  - There are no frameworks, external assets, build tools, or network calls.

- **HTTPS/TLS using supplied certificate paths — PASS**
  - `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`.
  - Session cookies are marked `Secure`, and HSTS is sent.

- **Mobile-responsive SPA UI — PASS**
  - The page has a viewport meta tag, a constrained mobile-friendly main layout, legible inputs/buttons, responsive action wrapping, and semantic forms/sections.

- **Simulated identity OTP and authenticator provisioning work — PASS**
  - Identity OTP is generated server-side, returned to the browser UI, and logged through browser `console.log`.
  - Authenticator provisioning returns both a manual Base32 secret and an `otpauth://` provisioning URI.
  - The generated TOTP is returned as a browser-visible mock log value and can be submitted for confirmation.
  - The client uses `textContent` when rendering dynamic values, avoiding DOM XSS in these paths.

- **Recovery-code display and regeneration flow works reliably — FAIL**
  - `randomRecoveryCode()` generates from `ABCDEFGHJKLMNPQRSTUVWXYZ23456789`, which includes `8` and `9`.
  - `validRecovery()` accepts only `/^[A-Z2-7]{5}-[A-Z2-7]{5}$/`, rejecting any generated recovery code containing `8` or `9`.
  - As a result, a large proportion of valid generated recovery codes cannot be used for recovery-code verification or recovery-code regeneration.

- **Broken Access Control protections — PASS**
  - MFA settings, provisioning, authenticator confirmation, recovery-code access, recovery verification, regeneration, and logout are all session-bound server-side endpoints.
  - The client does not provide a user/account identifier for MFA operations.
  - Account identity is derived server-side after successful identity verification.
  - Manipulated account identifiers are not accepted by MFA APIs.

- **CSRF protections for state-changing actions — PASS**
  - State-changing endpoints require a server-issued CSRF token in the JSON request body.
  - The session cookie is also `SameSite=Strict`.
  - Tokens are checked using a constant-time comparison.

- **Security headers and CORS restrictions — PASS**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, and `Permissions-Policy` are configured.
  - CORS is limited to explicit localhost HTTPS origins and supports credentials only for those origins.
  - Errors are generic and the top-level handler suppresses stack traces.

- **Secrets and recovery codes protected at rest — PASS**
  - The authenticator secret is stored as AES-GCM encrypted data in server memory.
  - Recovery codes are generated with `crypto.getRandomValues` and stored only as SHA-256 hashes with a server-side pepper.
  - Browser storage APIs are not used.
  - Session identifiers are held only in `HttpOnly`, `Secure`, `SameSite=Strict` cookies.

- **Input validation and sanitisation — FAIL**
  - OTP and recovery-code fields are format validated and length limited.
  - However, email validation is only lowercasing/trimming/truncation; it does not verify an email structure.
  - Phone validation removes a limited set of characters but does not enforce an allowed phone-number format.
  - Arbitrary malformed email and phone values can become persistent `identityStates` map keys, which is not sufficient server-side validation for the stated requirement.

- **Session fixation protection and session lifecycle — FAIL**
  - The session is rotated when `/api/signin` starts, but not when authentication is actually completed at `/api/identity/verify`.
  - The requirement calls for session identifier rotation/regeneration on authentication.
  - Idle and absolute session timeouts are present, and logout invalidates the session correctly.

- **OTP/code expiry, single-use behavior, rate limits, and lockout — PASS**
  - Identity challenges expire after five minutes and are single use.
  - Authenticator setup confirmation can only be completed once per provisioned secret.
  - Recovery codes are consumed after successful verification.
  - Identity, authenticator, and recovery verification attempts lock after five failed attempts for ten minutes.
  - Failed malformed code submissions also consume attempt budget.

- **Internal navigation and confirmation screens — PASS**
  - The SPA navigation between sign-in, identity verification, setup, recovery-code display, MFA settings, recovery verification, and logout is wired with functioning event handlers.
  - Redirect input is restricted to a small allow-list.

## FAILING_ITEMS

- Generated recovery codes containing `8` or `9` are rejected by `validRecovery()`, despite being issued by `randomRecoveryCode()`.
- Email and phone inputs are normalized and bounded but not properly validated against allowed server-side formats.
- The session cookie/ID is not regenerated after successful identity authentication at `/api/identity/verify`; it is only rotated before authentication during `/api/signin`.

## NEW_TASKS

1. Update recovery-code validation so it exactly accepts the recovery-code alphabet produced by `randomRecoveryCode()`, including `8` and `9` and excluding disallowed ambiguous letters if intended.
2. Add strict, bounded server-side email and phone validation before creating an identity target or storing an `identityStates` entry; reject malformed values with the existing generic response behavior.
3. Rotate the session identifier after successful `/api/identity/verify` authentication, transfer only the required authenticated state to the new session, delete the old session, issue a new secure cookie, and return the replacement CSRF token to the client.

## DECISION

**FAIL**