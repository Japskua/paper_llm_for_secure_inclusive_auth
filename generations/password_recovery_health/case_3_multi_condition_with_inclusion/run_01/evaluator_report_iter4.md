## SUMMARY

The artifact is a valid single-file Bun HTTPS application implementing a browser-rendered password recovery, sign-in, MFA, privacy acceptance, and appointment-confirmation flow. It uses inline HTML/CSS/vanilla JavaScript within `app.ts`, serves over TLS using the required certificate paths, avoids external assets/network calls, and includes server-side session, CSRF, token, password-hashing, throttling, and access-control protections. The simulated recovery and MFA values are logged in the browser as required.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no build tools/frameworks**
  - All server logic, HTML, CSS, and browser JavaScript are contained in `app.ts`.
  - The code uses `Bun.serve` directly and does not rely on bundlers, compilation steps, frameworks, or external assets.

- **PASS — TLS and HTTPS enforcement**
  - The HTTPS server loads `certs/cert.pem` and `certs/key.pem`.
  - Startup fails safely if certificates are missing.
  - A separate HTTP listener performs a fixed redirect to the HTTPS localhost origin.
  - Session cookies are marked `Secure`, `HttpOnly`, `SameSite=Strict`, and use the valid `__Host-` cookie prefix configuration.

- **PASS — Clear recovery and authentication workflow**
  - The SPA includes the required password-reset sequence: recovery request, manual code entry, code verification, new-password creation, completion, sign-in, MFA, privacy acceptance, and appointment confirmation.
  - Recovery and MFA codes can be manually entered.
  - Browser-side simulated delivery values are written to `console.log` and shown in the application log panel.
  - Internal route transitions (`/`, `/reset`, `/signin`, `/account`, `/appointment`) are handled by the Bun server and client-side navigation.

- **PASS — ADHD/inclusivity and low-stress UX**
  - The interface presents a visible numbered progress list and clear one-step instructions.
  - It avoids countdown pressure; expiry is explained without live time pressure.
  - A persistent help/safe-sign-in section is available at every stage.
  - The user can pause and resume server-backed workflow state.
  - The UI uses semantic headings, labels, focus styling, responsive layout, restrained visual design, and readable feedback notices.

- **PASS — CSRF protection and session handling**
  - A cryptographically random CSRF token is generated per session.
  - All `/api/` POST endpoints require a valid session and a timing-safe CSRF-token comparison.
  - Sensitive workflow state, reset records, MFA state, authentication status, and privacy acceptance are maintained server-side rather than trusted from client input.

- **PASS — Access control / IDOR protections**
  - Reset records are bound to the originating session and intended mock account.
  - Password reset requires a current, unexpired, unused, verified, session-bound token.
  - MFA is session-bound and required before setting `authenticated`.
  - Privacy acceptance and appointment confirmation require an authenticated session.
  - Protected page routes redirect unauthenticated users to the sign-in route.

- **PASS — XSS and injection protections**
  - Request values are not interpolated into HTML responses.
  - Browser-rendered dynamic text uses `textContent`, not `innerHTML`.
  - Server input fields are type-checked and length-limited.
  - A nonce-based CSP restricts scripts and styles to the generated trusted nonce.
  - The client has no event-handler attributes, dynamically loaded scripts, or external script sources.

- **PASS — Secure reset-token behavior**
  - Reset tokens are generated with cryptographically secure randomness and are 256-bit values represented as 64 hex characters.
  - Tokens expire after 10 minutes.
  - Tokens are bound to the requesting session, verified before password replacement, and deleted after use.
  - Expired and used reset records are cleaned up.
  - Invalid reset-code submissions are throttled and eventually locked out.

- **PASS — Password policy and password storage**
  - Passwords are hashed with Bun Argon2id rather than stored in plaintext.
  - The new-password policy enforces 12–128 characters, uppercase, lowercase, numeric, and symbol requirements.
  - Whitespace and obvious predictable prefixes are rejected.

- **PASS — Brute-force and authentication protections**
  - Sign-in failures are counted and lock the account temporarily after repeated failures.
  - Reset verification is rate-limited and locked after repeated invalid attempts.
  - MFA verification is rate-limited and locked after repeated failures.
  - MFA codes are cryptographically generated, six-digit values with 10-minute expiry.

- **PASS — Security headers and production-safe responses**
  - CSP, HSTS, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, COOP, CORP, and no-store cache controls are configured.
  - Unknown routes return a generic 404 response.
  - Unexpected server errors return a generic 503 response without stack traces or debug data.
  - The service has no directory listing behavior or external outbound requests.

- **PASS — SSRF, open redirect, and phishing mitigation**
  - The application does not make outbound network requests, eliminating SSRF behavior.
  - HTTP redirects are fixed to the local HTTPS origin and only preserve known internal paths.
  - The UI includes repeated anti-phishing guidance not to share passwords or verification codes via email, phone, or text.

## FAILING_ITEMS

- None identified.

## NEW_TASKS

1. No remediation tasks required.

## DECISION

PASS