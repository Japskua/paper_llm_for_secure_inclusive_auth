## SUMMARY

The artifact is a valid single-file Bun application implementing a secure, functional password-recovery SPA. It serves the HTML, CSS, and vanilla browser JavaScript directly from `app.ts`, uses the required TLS certificate paths, and implements recovery, code verification by link or manual entry, password reset, MFA, sign-in, and privacy-condition acceptance. Security controls—including server-side sessions, CSRF validation, token expiry/single use, bcrypt hashing, throttling, CSP, HTTPS, and output-safe DOM updates—are implemented without evident runtime or TypeScript errors.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application / no compilation or external assets**
  - The entire server, HTML template, CSS, and browser JavaScript are in `app.ts`.
  - It uses `Bun.serve(...)` directly, with no framework, bundler, compiler, external scripts, or external network calls.

- **PASS — TLS and HTTPS enforcement**
  - Bun is configured with `certs/cert.pem` and `certs/key.pem`.
  - Requests whose URL is not HTTPS are rejected.
  - Cookies are marked `Secure`, and HSTS is supplied on HTML and JSON responses.

- **PASS — Password recovery UI and complete end-to-end flow**
  - The UI provides recovery request, recovery-code verification, strong-password reset, MFA verification, sign-in, and privacy acceptance.
  - Successful actions transition the user through the relevant screens.
  - Direct navigation to later screens does not bypass server-side authorization checks.

- **PASS — Manual recovery-code submission and recovery link**
  - The recovery code can be entered manually in the verification form.
  - The generated mock recovery link sets a fragment route containing the code and automatically attempts verification.
  - The fragment-based token does not get transmitted to the server as a URL path/query string or sent in referrer headers.

- **PASS — Browser-side mock delivery logging**
  - Recovery and MFA codes are returned only for the academic mock flow.
  - The browser logs them through `console.log(...)` via `audit(...)`.
  - Password values are not logged.

- **PASS — CSRF protection**
  - A cryptographically random CSRF token is generated per session.
  - Every state-changing API request requires the active session and a valid CSRF value.
  - The session cookie uses `HttpOnly`, `Secure`, and `SameSite=Strict`.

- **PASS — Access-control and IDOR protections**
  - Reset records are bound to both the current session and an opaque internal account ID.
  - Verification, reset, MFA, sign-in, and privacy acceptance all validate the appropriate prior state server-side.
  - Client-visible data does not include account IDs, usernames, folders, or other private account identifiers.

- **PASS — Reset-token security**
  - Reset token secrets are generated using `crypto.getRandomValues`.
  - Only a SHA-256 hash of the token secret is retained server-side.
  - Tokens expire after 15 minutes, are marked as used after reset, and are bound to the issuing session/account.
  - Verification attempts are throttled after repeated failures.

- **PASS — Password security and authentication**
  - Passwords are checked against a strong policy: 12–128 characters with uppercase, lowercase, numeric, and symbol requirements.
  - Passwords are stored using `Bun.password.hash(..., { algorithm: "bcrypt", cost: 12 })`.
  - Sign-in verifies the bcrypt hash and includes lockout/throttling after repeated failed attempts.
  - MFA is required after password reset before sign-in is allowed.

- **PASS — XSS and injection resistance**
  - User-controlled values are not interpolated into server-rendered HTML.
  - Browser-side status and log output use `textContent`, not unsafe HTML insertion.
  - Inputs are constrained with server-side validation.
  - CSP uses per-response nonces for the application’s trusted inline style and script blocks.

- **PASS — Secure response configuration**
  - HTML responses include CSP, HSTS, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and `Cross-Origin-Opener-Policy`.
  - Sensitive responses use `Cache-Control: no-store`.
  - Generic errors are returned rather than stack traces or debug information.

- **PASS — SSRF, open redirect, and social-engineering controls**
  - The application makes no outbound requests and accepts no externally supplied redirect URL.
  - Navigation is limited to known internal hash-based views.
  - The UI explicitly warns users not to share passwords, recovery codes, or security codes with staff or email senders.

- **PASS — Semantic and accessible UX structure**
  - The page uses semantic `header`, `main`, `nav`, `section`, `form`, `label`, and button elements.
  - Status messages use `role="status"` or `aria-live`.
  - Inputs have associated labels, appropriate autocomplete values, and visible focus styling.

## FAILING_ITEMS

- None identified.

## NEW_TASKS

1. None.

## DECISION

**PASS**