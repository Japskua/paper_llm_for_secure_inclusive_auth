## SUMMARY

The artifact is a well-structured single-file Bun application with a responsive mobile MFA flow, server-side session ownership checks, CSRF validation, TLS configuration, TOTP verification, encrypted MFA secrets, recovery-code generation, and browser-side simulation logs. The enrolment flow appears functional. However, the Content Security Policy permits arbitrary inline JavaScript through `'unsafe-inline'`, materially weakening the XSS protection expected from a secure CSP. Therefore, the artifact does not fully meet the security requirements.

## FUNCTIONAL_CHECK

- **Single-file `app.ts` Bun server with inline HTML/CSS/JavaScript and no build tooling: PASS**
  - The server, HTML template, CSS, browser JavaScript, and API logic are contained in one `app.ts`.
  - It uses `Bun.serve` directly and does not rely on frameworks, bundlers, external libraries, or external network calls.

- **Mobile-responsive MFA enrolment UI: PASS**
  - The page includes a viewport meta tag and responsive CSS.
  - The main content is constrained to a mobile-friendly width and controls become full-width at narrow viewports.

- **Sign-in, identity confirmation, TOTP provisioning, TOTP verification, recovery-code generation, confirmation, completion, and logout flow: PASS**
  - Hash-based routing gates users through the required stages.
  - The API state returned by `/api/me` prevents navigating directly to later enrolment stages.
  - TOTP verification and recovery-code generation endpoints are implemented and connected to the UI.

- **Authenticator secret and OTP available manually for simulation/testing: PASS**
  - Provisioning displays a Base32 secret.
  - A current test OTP is returned to the protected UI and written to the browser console through `console.log`.
  - The verification screen accepts a manually entered six-digit code.

- **Recovery codes are generated securely, displayed to the user, and logged only in the browser simulation log: PASS**
  - Codes use `crypto.getRandomValues`.
  - The recovery-code API returns codes for the authenticated user during generation.
  - The browser logs test values as explicitly required by the mock/simulation requirement.

- **Server-side authorization and IDOR protection on MFA endpoints: PASS**
  - Authenticated account identity is derived from the HttpOnly session cookie rather than client-supplied account identifiers.
  - The code rejects common client-supplied identity fields such as `userId`, `accountId`, `email`, `phone`, and related nested keys.
  - MFA settings are accessed through the session-owned account only.

- **CSRF protection on authenticated state-changing requests: PASS**
  - State-changing authenticated endpoints require an `X-CSRF-Token`.
  - Tokens are compared in constant time.
  - Requests must also have a same-origin HTTPS `Origin` matching the trusted host.

- **Secure cookie and session handling: PASS**
  - Session cookies use `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, and a `Max-Age`.
  - Sessions are rotated on login by deleting the prior session and generating a new token.
  - Idle and absolute session timeouts are enforced.
  - Logout invalidates the server-side session and expires the cookie.

- **OTP and recovery-code verification controls: PASS**
  - TOTP validation checks current and previous 30-second windows.
  - Provisioning attempts expire after five minutes and become single-use after successful verification.
  - Failed TOTP and recovery-code attempts lock after five failures for ten minutes.
  - Recovery codes are marked used after redemption.

- **Secrets protected at rest and generated with secure randomness: PASS**
  - TOTP secrets and recovery codes use `crypto.getRandomValues`.
  - TOTP secrets are AES-GCM encrypted before storage.
  - Recovery codes are SHA-256 hashed and also AES-GCM encrypted for authorized display.
  - No secrets or session tokens are written to browser storage or non-HttpOnly cookies.

- **HTTPS/TLS and HSTS configuration: PASS**
  - Bun is configured with the required certificate and key paths.
  - The application emits an HSTS header.
  - API requests containing `X-Forwarded-Proto: http` are rejected.

- **Input validation, generic errors, and redirect controls: PASS**
  - Email, phone, OTP, and recovery-code formats are validated server-side.
  - The app returns generic errors rather than exception details.
  - The application does not implement external redirects; client routing is limited to internal hash routes.

- **Security headers and clickjacking protection: FAIL**
  - CSP, HSTS, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, and `Permissions-Policy` headers are set.
  - However, the CSP includes `script-src 'self' 'unsafe-inline'`. This allows arbitrary injected inline JavaScript to execute and substantially undermines CSP as an XSS mitigation.
  - The application’s own inline script should be authorized with a nonce or hash instead of allowing all inline scripts.

- **Restricted CORS: PASS**
  - CORS headers are emitted only when the `Origin` exactly matches the trusted local HTTPS host.
  - Credentials are only enabled for that same trusted origin.

## FAILING_ITEMS

- **CSP is weakened by `script-src 'unsafe-inline'`.**
  - The current policy is:
    ```http
    script-src 'self' 'unsafe-inline'
    ```
  - Any successful HTML/DOM injection could run inline JavaScript despite CSP.
  - This is incompatible with the intent of the security-misconfiguration and XSS-protection requirements.

## NEW_TASKS

1. Replace the CSP `script-src 'unsafe-inline'` directive with nonce- or hash-based authorization for the application’s inline script.
2. Generate a cryptographically random CSP nonce per HTML response, add that nonce to the inline `<script>` element, and emit the matching `script-src 'self' 'nonce-…'` CSP directive.
3. Remove unnecessary inline HTML style attributes or authorize the inline `<style>` block using a nonce/hash so the CSP can avoid broad inline allowances where practical.

## DECISION

FAIL