## SUMMARY

The artifact is a single `app.ts` Bun application with an operational browser-based recovery flow, TLS configuration, CSRF validation, CSP nonces, token hashing, bcrypt password hashing, MFA, and throttling for verification/sign-in attempts. However, it has two security-design defects that prevent acceptance: server-side sessions never expire, and password state is globally shared rather than associated with a specific account/recovery context. These issues undermine secure session handling and account isolation.

## FUNCTIONAL_CHECK

- **Single-file Bun server + HTML/CSS/vanilla browser JavaScript: PASS**
  - The server, page template, styles, and client-side logic are all contained in `app.ts`.
  - No framework, bundler, compiler, or external assets are used.

- **TLS / HTTPS enforcement using provided certificates: PASS**
  - `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`.
  - Requests whose URL protocol is not `https:` are rejected.

- **Security headers and CSP: PASS**
  - The HTML response includes HSTS, CSP with a per-response nonce, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and `Cross-Origin-Opener-Policy`.
  - The CSP allows only same-origin resources and nonce-authorized inline style/script blocks.

- **CSRF protection on sensitive actions: PASS**
  - A cryptographically random CSRF token is generated per session.
  - Every state-changing API action requires and validates the CSRF token.
  - The session cookie uses `HttpOnly`, `Secure`, and `SameSite=Strict`.

- **Session security and lifecycle: FAIL**
  - The cookie has `Max-Age=1800`, but server-side session objects in `sessions` never expire or are removed.
  - A copied/stolen `recovery_session` cookie can remain valid indefinitely on the server even after its browser-side expiration time.
  - Authenticated state, CSRF tokens, and recovery state can consequently persist without a server-enforced lifetime.

- **No user/private identifier exposure: PASS**
  - The UI does not expose usernames, patient identifiers, account existence, course folders, or other private data.
  - Recovery responses are intentionally generic to reduce account enumeration.

- **Recovery token quality, expiration, and verification: PASS**
  - Recovery IDs and secrets are generated using cryptographic randomness.
  - Only a SHA-256 hash of the token secret is stored.
  - Tokens are scoped to the initiating session, expire after 15 minutes, and are marked used after password reset.
  - Verification attempts are throttled after repeated failures.

- **Manual recovery-code submission and recovery link functionality: PASS**
  - The mock recovery code is shown in the browser console and mock UI.
  - The user can either paste the code manually or follow the fragment-based mock recovery link.
  - The fragment-based link avoids sending the recovery token in an HTTP request/referrer.

- **XSS / injection prevention: PASS**
  - User-controlled values are not interpolated into HTML.
  - Browser-visible dynamic output uses `textContent`.
  - The page uses a restrictive CSP and no external/untrusted scripts.

- **Strong password policy and secure password storage: PASS**
  - Passwords require 12–128 characters with uppercase, lowercase, numeric, and symbol characters.
  - Passwords are stored with bcrypt using cost 12.
  - Passwords are neither logged nor rendered back into the UI.

- **MFA and brute-force protection: PASS**
  - A six-digit additional security code is required after password reset.
  - MFA and sign-in attempts are locked for one minute after five failed attempts.
  - The mock MFA code is logged in the browser console and displayed in the academic mock UI as required.

- **Account isolation / password ownership: FAIL**
  - `passwordHash` is a single global variable shared by every session and every recovery attempt.
  - A password reset in one session overwrites the password used by all previously reset/authentication-capable sessions.
  - For example, session A can complete recovery and MFA; session B can then reset the global password; session A can sign in using session B’s new password because sign-in verifies against the same global `passwordHash`.
  - This does not model password data as belonging to a specific account/recovery subject and violates proper access-control/account-isolation expectations.

- **Privacy-condition acceptance access control: PASS**
  - Privacy acceptance requires a successfully authenticated session.
  - The acceptance operation is CSRF-protected.

- **No external network calls / safe URL handling: PASS**
  - The client only calls same-origin `/api/recovery`.
  - There are no redirects, user-controlled outgoing URLs, or external resources.

- **Browser mock logging requirement: PASS**
  - Recovery delivery, MFA delivery, verification, sign-in, and privacy acceptance events are logged through browser-side `console.log`.
  - Passwords are not logged.

## FAILING_ITEMS

- Server-side sessions have no expiration timestamp, expiration validation, or cleanup. The cookie lifetime does not enforce a backend session lifetime and can be bypassed by replaying a retained cookie value.
- The application stores the password hash in one global `passwordHash` variable rather than binding it to an account or recovery subject. This permits cross-session password interference and breaks account isolation.

## NEW_TASKS

1. Add an `expiresAt` field to `Session`, set it when creating a session, and reject/delete expired sessions before serving the page or processing any API action.
2. Add periodic or opportunistic cleanup of expired entries from both `sessions` and `resets`.
3. Replace the global `passwordHash` variable with account-scoped password state, such as a server-side account record keyed by a non-exposed internal account identifier.
4. Bind each reset record and authenticated session to the same internal account identifier, and ensure sign-in verifies only that account’s stored password hash.
5. Ensure a reset in one account/recovery context cannot alter sign-in behavior or password verification for any other session/account context.

## DECISION

FAIL