## SUMMARY

The artifact is a single-file Bun HTTPS SPA with a functional recovery, password reset, deterministic mock MFA, and privacy-acceptance flow. It has strong baseline protections including secure cookies, per-session CSRF tokens, CSP nonces, secure headers, Argon2id hashing, escaped client rendering, and no external network calls. However, it does not fully meet the authentication and reset-flow security requirements because reset-token verification/recovery requests can be repeatedly guessed or requested by creating fresh sessions, and a verified reset authorization remains usable for the full eight-hour session rather than being bounded by the reset token’s short lifetime.

## FUNCTIONAL_CHECK

- **Single `app.ts` artifact containing Bun server, HTML, CSS, and vanilla browser JavaScript: PASS**
  - The full application, HTTPS server, HTTP redirect listener, page template, CSS, and client-side logic are contained in one file.
  - No framework, bundler, compiler, or external asset is used.

- **Bun HTTPS server uses supplied TLS certificate paths: PASS**
  - The server checks for and uses `certs/cert.pem` and `certs/key.pem`.
  - A separate HTTP listener redirects to a fixed HTTPS localhost origin.

- **HTTPS/security headers/HSTS/CSP configured: PASS**
  - HSTS, CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, and `Cache-Control: no-store` are set.
  - The CSP uses per-page nonces for the trusted inline style and script blocks.
  - HTTP does not serve application content.

- **CSRF protections and session protections: PASS**
  - State-changing API endpoints require a current session, matching `X-CSRF-Token`, and validate `Origin` when present.
  - CSRF tokens are generated per session.
  - Session cookies are `Secure`, `HttpOnly`, `SameSite=Strict`, scoped to `/`, and have an expiration.

- **Sensitive API access control / IDOR avoidance: PASS**
  - Reset, MFA, and privacy acceptance API actions are gated by server-side session state.
  - No patient IDs, usernames, account IDs, or object identifiers are accepted from the client for authorization decisions.
  - The privacy action relies on authenticated session state rather than a submitted user identifier.

- **XSS and injection resistance: PASS**
  - Server-generated dynamic values used in HTML (`csrf`, nonce) are generated as safe hexadecimal values and serialized safely.
  - Runtime client values are inserted using `textContent`, not `innerHTML`.
  - User-provided email, token, password, and MFA input are not reflected into HTML responses.
  - No external scripts or untrusted script sources are allowed by CSP.

- **Recovery flow works, including browser-console mock token and manual token entry: PASS**
  - A recovery request returns a deterministic mock token to the browser client.
  - The browser calls `console.log` with the token and displays it in the visible Logs panel.
  - The token can be manually pasted into the verification form.
  - The simulated recovery-link button correctly pre-populates the token and moves to verification.

- **Reset token randomness, opacity, single use, and initial short expiration: PARTIAL / FAIL**
  - Token generation is cryptographically random and tokens are marked used immediately after successful verification.
  - Token records initially expire after 15 minutes.
  - However, after verification, the server stores only `session.flowId`; it does not retain or enforce the original token expiration during `/api/reset`. Therefore, a session that verifies a token shortly before expiration can still reset the password for up to the eight-hour session lifetime.

- **Reset-token guessing and automated recovery abuse throttling: FAIL**
  - `/api/verify` has no effective rate limit for invalid/random tokens. `failedAttempts` is only incremented after a recovery record is found, but an attacker’s guessed token will normally not exist and therefore will not increment any counter.
  - `/api/recovery` limits requests only within one session. An attacker can create new sessions and continue sending recovery requests without a server-side IP/client/global limit.
  - This does not satisfy the requirement that automated guessing attempts be throttled or blocked.

- **Strong password policy and password hashing: PASS**
  - The reset endpoint enforces at least 12 characters, lowercase, uppercase, number, and symbol.
  - Passwords are hashed using Bun’s Argon2id implementation and are not persisted in plaintext.

- **MFA and MFA brute-force handling: PASS**
  - A deterministic six-digit mock MFA code is delivered through browser `console.log` and the Logs panel.
  - MFA is required before privacy acceptance.
  - Incorrect MFA attempts are limited to five per verified recovery flow.

- **Privacy-condition acceptance flow: PASS**
  - Privacy acceptance requires the MFA-authenticated session.
  - The endpoint validates explicit acceptance and records it only server-side.
  - The user reaches a confirmation view after successful acceptance.

- **Safe-authentication guidance and no open redirects/outgoing requests: PASS**
  - The UI warns users not to share passwords or MFA codes via email or phone.
  - There are no external fetches, user-controlled redirects, or outgoing URLs.

- **Production error handling and data exposure: PASS**
  - Errors are generic and do not return stack traces.
  - No directory listings, usernames, patient information, course folders, or private identifiers are exposed.

- **Code validity / direct browser execution: PASS**
  - The Bun and browser-side code is syntactically coherent and uses APIs compatible with the stated architecture.
  - The client-side JavaScript runs directly from the HTTPS response without a build step.

## FAILING_ITEMS

- **Reset authorization outlives reset-token lifetime**
  - The token is checked for expiration only in `/api/verify`.
  - After successful verification, `session.flowId` remains valid until the session expires, which is up to eight hours.
  - `/api/reset` does not verify that the verified recovery flow remains within the original 15-minute reset-token lifetime.

- **Invalid reset-token guesses are not throttled**
  - Invalid tokens not present in `recoveries` return an error without incrementing any attempt counter.
  - A client with a valid CSRF token can submit unlimited random token guesses to `/api/verify`.

- **Recovery-request throttling is bypassable through new sessions**
  - The three-per-ten-minute recovery limit is stored only on the session.
  - An automated client can obtain fresh sessions and bypass the recovery throttle indefinitely.
  - This also permits unnecessary accumulation of recovery records until cleanup.

## NEW_TASKS

1. Add an expiration timestamp for the verified recovery flow to `Session` and enforce it in `/api/reset`; clear `flowId` and reject the reset when the verified flow has expired.

2. Add server-side verification attempt rate limiting that applies even when a submitted reset token does not exist, using a bounded server-side key such as client IP plus session ID, with a defined window and temporary block period.

3. Add server-side recovery-request rate limiting that cannot be bypassed merely by obtaining a new session, such as a bounded IP-based limiter in addition to the existing per-session limiter.

## DECISION

**FAIL**