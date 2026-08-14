## SUMMARY

The artifact fails validation because `app.ts` is incomplete and syntactically invalid: it ends partway through the `headers` function at `const h`. Bun cannot start the server, so no HTML, client UI, API endpoints, enrolment flow, TLS serving, or security controls can be exercised. Although the visible portion includes promising helper functions for cryptography, sessions, TOTP, and recovery codes, it does not constitute a runnable single-file application.

## FUNCTIONAL_CHECK

- **Single-file Bun server serves the complete HTML/CSS/vanilla-JS SPA: FAIL**  
  The file is truncated before server construction, routing, HTML generation, and response handling. No client UI is present in the supplied artifact.

- **No frameworks, bundlers, compilers, or external assets: PASS (for visible code only)**  
  The visible code uses Bun/TypeScript and Node filesystem imports only. However, the application does not run due to syntax failure.

- **TLS is configured using `certs/cert.pem` and `certs/key.pem`: PARTIAL / FAIL**  
  The artifact checks that these files exist, but it never reaches or shows a Bun server configuration that loads and uses the certificate and key to serve HTTPS.

- **Mobile-responsive, legible MFA enrolment interface: FAIL**  
  No HTML, CSS, viewport configuration, semantic page structure, responsive styles, icons, or client-side UI is included.

- **Dyslexia-inclusive UX requirements: FAIL**  
  There is no visible interface implementing short instructions, readable typography, generous spacing, hints, prominent current steps/actions, input examples, retry/re-request controls, or copy-to-clipboard support.

- **Identity-verification code generation and verification: FAIL**  
  Helper functions for generating and hashing a pending identity code exist, but no endpoints or UI submit flow invoke them. The identity code is also not shown as being logged in the browser as required for mocks.

- **Authenticator provisioning via QR/provisioning URI and manual secret entry: FAIL**  
  `uri(secret)` exists, but no provisioning endpoint or UI displays it, generates a QR code, provides a copy control, supports manual setup, or logs the secret in the browser.

- **TOTP verification works and is single-use/time-bound: PARTIAL / FAIL**  
  The visible `verifyTotp` implementation attempts to enforce single-use counters and accepts current/previous 30-second windows. However, there is no callable endpoint or UI flow, so it cannot be used. Further, no client-side mock output is present.

- **Recovery codes are securely generated, displayed once, and can be verified: PARTIAL / FAIL**  
  The code includes cryptographically random generation outside test mode and PBKDF2 hashing for stored recovery codes. However, no recovery-code generation, display, download/copy experience, regeneration route, confirmation route, or verification endpoint is present.

- **Mocks are logged in the browser and deterministic values are available for testing: FAIL**  
  `FIXTURES` exists server-side, but the requirements explicitly require mocks to use `console.log` in the browser and for OTP/recovery values to be returned to the UI and logged there. No browser JavaScript exists.

- **Server-side authorization on every MFA endpoint / no IDOR: FAIL**  
  Session types and a hard-coded user ID exist, but no actual MFA endpoints or request authorization checks are supplied. The requirement cannot be verified or satisfied.

- **CSRF protection on state-changing requests: FAIL**  
  Sessions include a `csrf` field, but no token issuance, client submission, request validation, or state-changing routes are present.

- **Secure response headers (CSP, HSTS, nosniff, anti-clickjacking): FAIL**  
  A `headers` function starts but is incomplete. No actual HTTP responses set CSP, HSTS, `X-Content-Type-Options`, `frame-ancestors`, or `X-Frame-Options`.

- **Secure session cookies and secure session lifecycle: PARTIAL / FAIL**  
  Cookie helper strings include `HttpOnly`, `Secure`, and `SameSite=Strict`. However, no server response sets them, no login/session rotation is implemented, and no complete timeout/invalidation/logout behavior is wired to routes.

- **No secrets, OTPs, backup codes, or session tokens in logs/URLs/error output: FAIL**  
  The code is incomplete and cannot establish this. Also, the requirement asks that test mocks be shown in the browser console, which must be carefully limited to test/demo values and not session identifiers. No implementation is provided.

- **Encryption/hashing at rest and cryptographically secure generation: PARTIAL / FAIL**  
  The visible code encrypts OTP secrets with AES-GCM and uses PBKDF2 hashes with random salts for backup codes. Random values use `crypto.getRandomValues`. However, no persistence lifecycle or endpoint integration exists. Additionally, when `MFA_SERVER_KEY` is absent, a new random encryption key is generated each process start, making previously encrypted records undecryptable after restart.

- **Input validation, output encoding, and redirect allow-list: FAIL**  
  No request handlers, input schemas, HTML escaping/output encoding, or redirect implementation are supplied.

- **Rate limiting and lockout for failed verification: FAIL**  
  `security` and `State` are declared and `LOCK_MS` exists, but no failed-attempt counting, lockout enforcement, reset logic, or API/UI messaging is implemented.

- **Generic production errors / debug disabled / restricted CORS: FAIL**  
  No error handling, CORS policy, or response routing is supplied.

- **Internal links and enrolment navigation function correctly: FAIL**  
  No pages, routes, links, or SPA navigation logic exists.

- **Code validates and runs directly with Bun 1.3.0: FAIL**  
  The artifact has an unfinished declaration (`const h`) and lacks closing implementation code. It is not syntactically valid TypeScript.

## FAILING_ITEMS

- `app.ts` is truncated and syntactically invalid at:
  ```ts
  function headers(nonce?: string, origin?: string | null) {
    const h
  ```
  This prevents Bun from parsing or executing the file.

- There is no `Bun.serve(...)` server definition, HTTPS TLS configuration, request router, static SPA response, or API response implementation.

- No HTML template, CSS, browser JavaScript, semantic markup, mobile viewport settings, or responsive MFA UI is included.

- No browser-side `console.log` calls expose deterministic mock identity OTPs, authenticator secrets/TOTP test values, or recovery codes as required.

- Session, CSRF, authorization, lockout, CORS, headers, and logout helpers are declared or partially prepared but are never enforced on actual requests.

- No state-changing MFA routes exist for identity verification, authenticator provisioning/confirmation, enabling MFA, recovery-code acknowledgement, backup-code regeneration, or logout.

- No accessibility/inclusivity implementation exists: no copy buttons, QR presentation, manual provisioning path, hints, retry/re-request paths, clear errors, or low-reading-load screen flow.

- TLS certificate existence is checked, but certificates are not loaded into a Bun HTTPS server.

- The fallback random `SERVER_KEY` is process-local and changes on restart; encrypted persisted MFA records would become undecryptable unless a stable 32-byte `MFA_SERVER_KEY` is configured.

- There is no evidence of validation and escaping at request/response boundaries because the boundaries themselves are absent.

## NEW_TASKS

1. Complete `app.ts` so it is valid TypeScript, including the unfinished `headers` function and all missing closing code.

2. Implement a `Bun.serve` HTTPS server in the same file that reads `certs/cert.pem` and `certs/key.pem`, serves the SPA, and returns generic non-verbose errors.

3. Add a complete inline HTML template with semantic mobile-responsive CSS and vanilla browser JavaScript; include viewport metadata and dyslexia-friendly typography, spacing, concise wording, and predictable step navigation.

4. Implement browser UI screens and internal navigation for sign-in/session establishment, identity-code verification, authenticator setup, authenticator-code verification, recovery-code display/acknowledgement, backup-code use, MFA confirmation, and logout.

5. Implement authenticated API routes and enforce session ownership server-side on every MFA read/write route; derive the account exclusively from the authenticated session and never accept a user ID as an authority.

6. Issue and validate CSRF tokens for every state-changing endpoint, with same-origin/origin checks and `SameSite=Strict` secure HttpOnly cookies.

7. Complete the secure-header implementation and apply it to every response: CSP with a per-response nonce where required, HSTS, `X-Content-Type-Options: nosniff`, and `frame-ancestors 'none'` and/or `X-Frame-Options: DENY`; restrict CORS to the configured trusted origins.

8. Wire the existing cryptographic helpers into complete endpoint flows: encrypt TOTP secrets before storage, hash recovery codes before storage, verify TOTP/recovery codes, mark successful codes single-use where required, and never return stored encrypted/hash values to the client.

9. Implement server-side validation for every input and safe response rendering/JSON handling; add an internal redirect allow-list if redirects are used.

10. Implement failed-attempt tracking, rate limiting, five-minute lockout enforcement, and clear generic errors that explain how to fix invalid codes without account enumeration.

11. Implement session creation/rotation, idle and absolute expiry checks, logout invalidation, and cookie clearing; ensure session IDs and CSRF tokens are never logged or exposed to browser storage.

12. Add the required deterministic test-mode browser logs for the simulated identity OTP, provisioning secret/URI or test authenticator code, and recovery codes; do not log secrets or tokens outside the explicit test/mock flow.

13. Add QR presentation and accessible copy-to-clipboard controls for the provisioning URI/secret and recovery codes, while retaining manual entry paths and retry/re-request controls.

14. Require a stable valid 32-byte `MFA_SERVER_KEY` in environments where encrypted MFA records must survive restarts, rather than relying on the process-generated fallback key.

## DECISION

**FAIL**