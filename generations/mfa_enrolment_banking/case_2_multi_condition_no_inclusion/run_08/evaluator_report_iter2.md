## SUMMARY

The artifact is a single-file Bun/TypeScript MFA enrolment SPA with a functional mobile-oriented flow, simulated browser-side mock logging, TLS configuration, server-side session-derived authorization, CSRF checks, encrypted OTP-secret handling, hashed recovery codes, and verification lockouts. Most functional and security requirements are implemented correctly. However, the CSP uses a predictable, hard-coded nonce, which weakens the intended XSS protection of the CSP. It also does not provide clear code comments mapping all required security sections (2–4) back to the implementation.

## FUNCTIONAL_CHECK

- **Single `app.ts` file containing Bun server, HTML, CSS, and vanilla browser JavaScript: PASS**
  - The full server and SPA HTML template are contained in the supplied `app.ts`.
  - No framework, bundler, compiler step, or external asset/network dependency is used.

- **Bun TLS server using the required certificate paths: PASS**
  - `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`.
  - The server advertises HTTPS and applies HSTS headers.

- **Mobile-responsive, legible SPA UI: PASS**
  - The page includes an appropriate viewport meta tag.
  - CSS uses responsive layout rules and a mobile breakpoint that makes buttons full-width and recovery codes single-column on narrow screens.

- **Sign-in, identity verification, authenticator provisioning, OTP verification, recovery-code display, regeneration, verification, and logout flow: PASS**
  - The UI and server endpoints support the required enrolment path.
  - State-changing calls use server endpoints and work through hash-based SPA navigation.
  - Manual authenticator-secret submission is supported in `/api/mfa/verify`.

- **Mocks shown in the browser UI and browser console: PASS**
  - Identity verification codes, provisioning secrets, OTPs, and recovery codes are returned to the UI flow.
  - The browser client calls `console.log` through `log(...)` for the test-only mock values.
  - The server does not log OTPs, secrets, backup codes, or session values.

- **Server-side authorization and IDOR prevention for MFA endpoints: PASS**
  - MFA endpoint authorization is derived only from the authenticated server-side session (`session.accountId`).
  - No MFA endpoint accepts a user/account identifier from the client.
  - MFA settings, provisioning, recovery-code operations, and status checks require authenticated session ownership and identity verification.

- **CSRF protections on state-changing requests: PASS**
  - State-changing endpoints require a matching `X-CSRF-Token`.
  - CSRF validation also checks a trusted same-origin HTTPS `Origin`.
  - Session cookies use `SameSite=Strict`.

- **Secure session handling: PASS**
  - Cookies are configured with `HttpOnly`, `Secure`, `SameSite=Strict`, and the `__Host-` cookie naming convention.
  - A new session is created after successful authentication, preventing session fixation.
  - Idle and absolute timeouts are enforced server-side.
  - Logout invalidates the server-side session and expires the cookie.

- **Security response headers and restricted CORS: FAIL**
  - HSTS, `X-Content-Type-Options`, clickjacking protections, referrer policy, permissions policy, cache controls, and restricted CORS are present.
  - However, the CSP nonce is a static predictable constant: `const NONCE = "mfa-enrolment-ui-v1";`.
  - A CSP nonce must be cryptographically random and unique per HTML response. A known reusable nonce allows a successful HTML injection vulnerability to bypass the nonce-based CSP by injecting a `<script nonce="mfa-enrolment-ui-v1">...</script>` element.

- **Secrets and recovery-code storage protections: PASS**
  - Authenticator secrets are generated with `crypto.getRandomValues` and AES-GCM encrypted before being stored in account state.
  - Recovery codes use cryptographically random values and are stored as SHA-256 digests with a server-side pepper.
  - Secrets, recovery codes, and session tokens are not persisted in browser storage or client-readable cookies.

- **Input validation, output safety, and redirect safety: PASS**
  - Server-side validation exists for email, phone, OTP, manual secret length, and recovery-code format.
  - The app has no database queries, so SQL injection is not applicable.
  - Client rendering of dynamic values uses `textContent` and DOM node creation rather than interpolating untrusted values into HTML.
  - There are no redirect parameters or external redirects.

- **Time bounds, single-use verification values, failure throttling, and generic errors: PASS**
  - Identity codes expire and are marked used after successful verification.
  - MFA provisioning is short-lived and can be used only once.
  - Recovery codes are marked used after successful verification.
  - Failed login, identity verification, MFA verification, and recovery-code attempts are limited and locked for 15 minutes after five failures.
  - Errors are generic and the top-level request handler suppresses stack traces.

- **Clear comments mapping code to all required security requirement sections: FAIL**
  - The artifact includes comments for Security Evaluation sections 1 and 5.
  - It does not include clear implementation-mapping comments for sections 2 (misconfiguration/headers/CORS), 3 (cryptographic failures), and 4 (input validation/output encoding/redirect handling), despite this being explicitly required.

## FAILING_ITEMS

- **Predictable CSP nonce**
  - `NONCE` is hard-coded as `"mfa-enrolment-ui-v1"` and reused for every response.
  - This is not a secure nonce-based CSP implementation and weakens the application’s XSS defense-in-depth.

- **Incomplete security-requirement mapping comments**
  - Code comments only explicitly map sections 1 and 5.
  - Required mappings for security sections 2, 3, and 4 are missing.

## NEW_TASKS

1. Replace the static `NONCE` constant with a cryptographically random nonce generated for each HTML document response; inject that nonce into the HTML `<style>`/`<script>` elements and into the corresponding response CSP header.
2. Add concise comments mapping the relevant implementation blocks to Security Evaluation sections 2, 3, and 4, including headers/CORS, cryptographic generation/storage, and validation/output encoding/redirect controls.

## DECISION

FAIL