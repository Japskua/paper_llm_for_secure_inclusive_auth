## SUMMARY

The artifact is a single `app.ts` Bun HTTPS application with a functional mobile MFA enrolment flow, server-side sessions, CSRF checks, encrypted TOTP secrets, hashed recovery codes, code expiry, and verification lockouts. Most functional and security requirements are addressed well. However, it does not provide a real scannable QR code despite presenting one, its CSP permits arbitrary inline script/style execution through `'unsafe-inline'`, and sign-in attempts are not rate-limited or locked out. These issues prevent acceptance.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no build tools or external assets.**  
  The complete Bun server, HTML, CSS, and vanilla browser JavaScript are contained in `app.ts`. It imports only Bun's built-in `serve` API and makes no external network requests.

- **PASS — HTTPS/TLS is configured using the specified certificate locations.**  
  The server reads `certs/cert.pem` and `certs/key.pem` and supplies them to Bun via `tls: { cert, key }`.

- **PASS — Mobile-responsive, legible SPA UI.**  
  The UI has a constrained mobile-width shell, usable touch-sized controls, spacing, plain-language content, progress steps, icons, help disclosures, and visible error/success notices.

- **PASS — Identity-verification flow works with mocked delivery.**  
  The identity-code endpoint generates a cryptographically random six-digit code, returns it only to the authenticated client for testing, logs it in the browser, enforces expiry, single use, retry messaging, attempt limits, and a lockout.

- **PASS — Authenticator provisioning and TOTP verification work server-side.**  
  Provisioning creates a random Base32 secret, encrypts it with AES-GCM, calculates RFC-6238-compatible HMAC-SHA-1 TOTP values, verifies a current/skewed time window server-side, and prevents reuse of an accepted TOTP time step.

- **FAIL — A QR-code option is presented but is not a real QR code.**  
  The `.qr` element is only a decorative `repeating-conic-gradient` square with text. It does not encode the generated `otpauth://` URI and cannot be scanned by an authenticator application. The “Copy authenticator QR link” action copies a provisioning URI, but that does not make the displayed visual QR option functional.

- **PASS — Manual authenticator setup is supported.**  
  The setup secret is displayed, may be copied, and can be pasted into the manual setup field. The user can also enter a six-digit authenticator code manually.

- **PASS — Recovery-code functionality works.**  
  Eight recovery codes are generated with cryptographic randomness, returned to the browser UI/console for the test flow, copied/downloaded by the user, hashed with per-code salts on the server, invalidated upon use, and regenerated securely.

- **PASS — MFA endpoints enforce session-based ownership and avoid IDOR.**  
  Account identity is derived only from the authenticated server-side session. The client never supplies an account ID or user ID to MFA endpoints, so manipulated identifiers cannot select another account.

- **PASS — CSRF protections are applied to state-changing authenticated endpoints.**  
  State-changing endpoints require a per-session CSRF token supplied via `X-CSRF-Token` or body field. Session cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`.

- **FAIL — CSP is weakened by `'unsafe-inline'`.**  
  The CSP includes `script-src 'self' 'unsafe-inline'` and `style-src 'self' 'unsafe-inline'`. This allows arbitrary injected inline JavaScript and styles to execute, materially weakening the XSS protection expected from a secure CSP. The inline app can remain single-file while using dynamically generated CSP nonces.

- **PASS — Other important security headers and browser protections are present.**  
  The server supplies HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, restrictive same-origin CORS behavior, no-store caching, referrer policy, and permissions policy headers.

- **PASS — Sensitive MFA material is not persisted in browser storage or non-HttpOnly cookies.**  
  No `localStorage`, `sessionStorage`, IndexedDB, or client-readable cookie is used for secrets, recovery codes, or session IDs. The server stores active/pending TOTP secrets encrypted and recovery codes as salted hashes.

- **PASS — MFA verification attempts are rate-limited and locked out.**  
  Identity-code verification, authenticator activation, and recovery-code use track failed attempts and enforce lockouts after five failures. Re-requesting an identity code or restarting provisioning does not clear the applicable failed-attempt state.

- **FAIL — Sign-in attempts are not rate-limited or locked out.**  
  `/api/signin` permits unlimited failed password attempts. The requirements call for rate-limiting and lockout of repeated failed verification/authentication attempts. Although MFA-code attempts are protected, repeated password authentication attempts are not.

- **PASS — Session lifecycle controls are substantially implemented.**  
  New sessions use cryptographically random identifiers after successful sign-in, have idle and absolute expiration checks, use secure cookie attributes, and are removed on logout.

- **PASS — Input validation and safe browser rendering are implemented.**  
  Server inputs are type-checked and format-validated for email, OTPs, and recovery codes. The browser UI uses DOM APIs and `textContent` rather than unsafe HTML injection for dynamic content.

- **PASS — Errors are generally specific, plain-language, and non-enumerating.**  
  Sign-in returns a generic credentials error, while MFA screens provide actionable messages such as entering six digits, requesting a new code, or waiting after lockout.

## FAILING_ITEMS

- The displayed “QR setup option” is a decorative pattern rather than a standards-compliant QR code encoding the generated `otpauth://totp/...` provisioning URI. Users cannot scan it with an authenticator app.
- The Content-Security-Policy allows `'unsafe-inline'` for scripts and styles, which undermines CSP/XSS protection.
- `/api/signin` has no failed-attempt counter, rate limit, temporary lockout, or equivalent anti-brute-force control.

## NEW_TASKS

1. Replace the decorative QR block with a real, scannable QR-code implementation that encodes the generated `otpauth://` URI, using code included directly in `app.ts` and no external assets or network calls.

2. Replace CSP `'unsafe-inline'` directives with per-response CSP nonces:
   - Generate a cryptographically random nonce in `page()`.
   - Add the nonce to the inline `<style>` and `<script>` elements.
   - Emit matching `script-src 'nonce-...'` and `style-src 'nonce-...'` CSP directives.
   - Remove `'unsafe-inline'`.

3. Add server-side sign-in failure protection:
   - Track failed sign-in attempts by a suitable server-side key, such as normalized email plus a rate-limit bucket.
   - Enforce a temporary lockout/rate limit after repeated failures.
   - Preserve the existing generic sign-in error message to avoid account enumeration.
   - Clear the failure state after a successful sign-in.

## DECISION

**FAIL**