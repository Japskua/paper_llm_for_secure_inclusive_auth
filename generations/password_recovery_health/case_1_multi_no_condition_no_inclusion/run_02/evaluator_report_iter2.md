## SUMMARY

The artifact is a single-file Bun HTTPS application that implements a functional password-recovery SPA with server-side session state, CSRF protection, random one-time recovery tokens, password hashing, MFA simulation, protected privacy acceptance, and appointment confirmation. The implementation is internally consistent, uses no external assets or network calls, and the client-side UI avoids unsafe DOM insertion.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application requirement:** The server, HTML template, CSS, and vanilla browser JavaScript are all contained in `app.ts`. No framework, bundler, compiler pipeline, or external asset is used. Bun can execute TypeScript directly.

- **PASS — HTTPS/TLS requirement:** `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`, and only a TLS listener is created on `https://localhost:3000`.

- **PASS — HTTPS enforcement and security headers:** The server rejects non-HTTPS request URLs and configures HSTS, CSP with per-response nonces, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, and no-store caching for the HTML application.

- **PASS — CSRF protection:** A cryptographically random CSRF token is generated per session, returned only through the same-origin session endpoint, and required on every state-changing API endpoint.

- **PASS — Secure session handling:** Session identifiers are opaque random values and are stored in a `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/` cookie using the `__Host-` prefix. Server-side session expiration is enforced.

- **PASS — Access control for sensitive routes:** Password reset, MFA verification, privacy acceptance, and appointment confirmation each enforce server-side state checks. Users cannot directly access later stages merely by altering the client-side route.

- **PASS — Recovery token protections:** Recovery tokens are generated with `crypto.getRandomValues`, are sufficiently long and non-predictable, expire after ten minutes, are single-use, and are consumed before password reset authorization is granted.

- **PASS — Manual code entry and verification-link flow:** The UI supports manual recovery-token submission. The mock recovery link navigates to the verification page with the token prefilled, and the flow remains server-validated.

- **PASS — Mock delivery requirements:** The browser logs the mock recovery token, mock recovery link, and mock MFA code via `console.log`. The token is also made available in the UI for the intended local evaluation flow.

- **PASS — Password policy and hashing:** Passwords must be 12–128 characters and include uppercase, lowercase, numeric, and symbol characters. Passwords are hashed using `Bun.password.hash` with bcrypt and are not persisted or logged in plaintext.

- **PASS — MFA implementation:** The recovery flow requires a second verification step after password reset. The deterministic MFA mock code is appropriate for the stated evaluation-only simulation requirement and is only accepted after a successful reset.

- **PASS — Brute-force mitigation:** Recovery-token and MFA-code verification attempts are throttled after five failures, returning HTTP 429 and blocking further attempts for one minute. The protected verification state is bound to the server-side session.

- **PASS — XSS/injection protections:** User-controlled values are not interpolated into HTML. The client uses `textContent`, `createElement`, and `replaceChildren` rather than `innerHTML`. The CSP prevents unauthorized scripts, and the only inline script/style blocks require server-generated nonces.

- **PASS — Privacy and identifier exposure:** The UI does not expose patient names, usernames, folders, account IDs, or other private identifiers. The internal protected account reference is never returned to the client.

- **PASS — Phishing and social-engineering guidance:** The UI explicitly tells users that staff will not request passwords or verification codes through email, phone, or messages.

- **PASS — No open redirect or SSRF behavior:** Navigation is limited to an allowlisted internal view set. There are no user-controlled outgoing URL requests, redirects, or external network calls.

- **PASS — Functional appointment workflow:** After recovery, password update, MFA, and privacy acceptance, the user can confirm an appointment request and receive a final confirmation view.

- **PASS — Error handling and debug exposure:** Server exceptions are caught and return a generic error without stack traces or debug data.

## FAILING_ITEMS

- None identified.

## NEW_TASKS

1. No changes required.

## DECISION

PASS