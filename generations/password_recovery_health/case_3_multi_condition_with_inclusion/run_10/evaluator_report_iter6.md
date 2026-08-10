## SUMMARY

The artifact meets the stated password-recovery, usability, security, and deployment requirements. It is a single `app.ts` file containing the Bun HTTPS server and a vanilla HTML/CSS/JavaScript SPA, with no external assets, build tooling, framework dependency, or network calls. The recovery flow is functional end-to-end: request code/link, verify by either mechanism, complete MFA, set a strong bcrypt-hashed password, sign in, and confirm privacy conditions.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun implementation**
  - The complete server, HTML template, CSS, and browser JavaScript are contained in `app.ts`.
  - It uses Bun directly and does not require a bundler, compiler, framework, or external dependency.

- **PASS — HTTPS/TLS support**
  - The server reads `certs/cert.pem` and `certs/key.pem` and configures `Bun.serve` with TLS.
  - The service is served as HTTPS at `https://localhost:3000`.
  - Requests marked `x-forwarded-proto: http` are rejected.

- **PASS — Strong security headers**
  - HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and no-cache headers are configured.
  - CSP uses a unique nonce for the generated style and script blocks.
  - Framing, plugins, unsafe base URLs, and untrusted form destinations are blocked.

- **PASS — CSRF protection**
  - A cryptographically random CSRF token is generated per server-side session.
  - Every sensitive POST route validates the session CSRF token.
  - The session cookie is `Secure`, `HttpOnly`, `SameSite=Strict`, scoped to `/`, and uses a random session identifier.

- **PASS — Access control and IDOR prevention**
  - Sensitive server transitions are session-bound and stage-gated.
  - There are no user- or record-ID-based routes that would permit IDOR.
  - Privacy confirmation requires an authenticated session in the correct `authenticated` stage.
  - Login is bound to the account associated with the completed reset flow.

- **PASS — Account-enumeration resistance**
  - Recovery requests use the same successful response pattern for known and unknown identifiers.
  - Unknown identifiers use a server-side sink account, avoiding disclosure of whether an account exists.

- **PASS — XSS and injection protections**
  - Browser-generated dynamic UI uses `textContent` and DOM construction rather than unsafe `innerHTML`.
  - User-provided values are validated server-side with restrictive formats and lengths.
  - No user input is interpolated into server-rendered HTML.
  - The CSP prevents arbitrary script execution.

- **PASS — Reset-token security**
  - Reset tokens and manual recovery codes are generated with cryptographically secure randomness.
  - Tokens are short-lived for ten minutes.
  - Verification values are invalidated after successful use.
  - Token verification is restricted to the requesting session and reset stage.
  - Verification works through both the simulated recovery link and the manual code.

- **PASS — Browser logging of mocks**
  - The simulated manual recovery code and recovery URL are logged using browser-side `console.log`.
  - The same simulated values are shown in the visible Logs panel.
  - Password values are explicitly not logged.

- **PASS — MFA implementation**
  - The reset flow requires an additional confirmation-code step before allowing a password change.
  - The deterministic simulated MFA code is delivered to the browser Logs panel after successful recovery verification.
  - MFA attempts are throttled.

- **PASS — Password policy and hashing**
  - New passwords must be 12–128 characters and include uppercase, lowercase, numeric, and symbol characters.
  - Password confirmation is required.
  - Passwords are hashed with Bun’s bcrypt implementation.
  - No plaintext password is stored or logged.

- **PASS — Brute-force mitigation**
  - Recovery, verification, MFA, password, and login attempts have progressive throttling keyed by action, identifier, and source IP.
  - Error messages tell the user to pause and retry rather than presenting unclear failures.

- **PASS — Safe routing and no open redirects**
  - The only navigable internal routes are `/`, `/recovery`, and `/verify`.
  - The verification link is generated from a fixed internal route.
  - No user-controlled redirect destination or outgoing URL is accepted.

- **PASS — Inclusive, ADHD-conscious UX**
  - The interface presents a visible four-step progress indicator.
  - Each stage has simple language and a prominent “Next step” reminder.
  - There are no surprise transitions, countdown UI, or session-time pressure messages.
  - Users can restart and request fresh recovery codes when needed.
  - Non-sensitive progress orientation is preserved in local storage without retaining passwords, identifiers, tokens, or codes.
  - Help content is visible at every stage and includes safe-authentication guidance.

- **PASS — End-to-end flow**
  - The stages are correctly enforced in sequence:
    1. Recovery request
    2. Recovery verification by code or link
    3. MFA confirmation
    4. Password change
    5. Sign-in
    6. Privacy-condition confirmation
  - Internal verification links function within the SPA/server routing model.

- **PASS — Error handling and production-safe responses**
  - Unknown routes return generic responses.
  - Internal exceptions return a generic service-unavailable response rather than a stack trace or debug output.
  - No directory listings or debug endpoints are present.

- **PASS — Code validity**
  - The TypeScript syntax and Bun APIs used are compatible with the intended Bun runtime model.
  - `Bun.password.hash`/`verify`, `Bun.serve`, TLS buffers, Web Crypto random generation, and top-level `await` are used appropriately.
  - The certificate files are expected at the required paths described in the requirements.

## FAILING_ITEMS

- None identified.

## NEW_TASKS

1. No remediation tasks are required.

## DECISION

PASS