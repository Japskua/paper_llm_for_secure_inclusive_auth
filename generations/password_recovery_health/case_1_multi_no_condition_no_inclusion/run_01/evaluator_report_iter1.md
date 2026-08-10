## SUMMARY

The artifact is a well-structured single-file Bun TLS SPA with a functional recovery UI, CSRF validation, CSP nonces, Argon2id password hashing, throttling, MFA simulation, and browser-console mock delivery logs. However, it does not fully meet the security requirements because reset tokens are reusable after successful verification, and the reset-request API leaks account recoverability through the presence or absence of `testToken`. These are concrete password-reset security and privacy failures.

## FUNCTIONAL_CHECK

- **Single `app.ts` file containing Bun server, HTML, CSS, and vanilla browser JavaScript: PASS**
  - The submitted artifact is one TypeScript file and embeds the full UI template, styles, client behavior, and Bun server.

- **No frameworks, no build tools, no external network calls/assets: PASS**
  - The UI uses standard HTML/CSS/JavaScript and same-origin `fetch` calls only.
  - There are no external scripts, stylesheets, images, API calls, or bundler dependencies.

- **Bun server uses supplied TLS certificate files and enforces HTTPS: PASS**
  - The server loads `certs/cert.pem` and `certs/key.pem`.
  - `Bun.serve` is configured with TLS, and plaintext HTTP cannot be served by the TLS listener.
  - HSTS and other secure headers are configured.

- **Recovery request flow functions with generic visible confirmation: PARTIAL / FAIL**
  - The visible `message` returned for valid and invalid identifiers is generic.
  - However, API response content differs: valid identifiers receive `testToken`, while invalid identifiers do not. An attacker can distinguish whether an account is recoverable by inspecting JSON responses.

- **Simulated reset delivery is returned to UI and logged in the browser: PASS**
  - For a valid simulated account, the browser receives `testToken`.
  - The client logs the reset token through `console.log` and displays it in the logs panel.
  - A reset-link UI is generated and functions.

- **Manual recovery-code submission and reset-link navigation function: PASS**
  - The reset token can be placed in the manual entry form.
  - The generated `/?reset=...` link loads the token into the verification form.
  - The URL query token is cleared with `history.replaceState`.

- **MFA verification is implemented and browser-console simulated: PASS**
  - Successful reset-token verification returns a deterministic mock MFA code.
  - The browser logs it with `console.log`.
  - MFA is required before password update.

- **Password policy and secure password hashing: PASS**
  - The policy requires 12–128 characters, uppercase, lowercase, numeric, and symbol characters, and disallows spaces.
  - Passwords are stored using `Bun.password.hash` with `argon2id`.
  - Password values are not logged or rendered.

- **CSRF protections on sensitive state-changing requests: PASS**
  - POST API routes require an `X-CSRF-Token`.
  - The token is session-specific.
  - The request `Origin` must exactly match the server origin.
  - The session cookie is `Secure`, `HttpOnly`, and `SameSite=Strict`.

- **Rate limiting / brute-force mitigation: PASS**
  - Reset requests are limited to three attempts per ten minutes per session.
  - Reset-token and MFA verification attempts are limited to five per ten minutes per session.

- **Password reset token randomness, expiry, and single-use behavior: FAIL**
  - Tokens are high-entropy and expire after 15 minutes.
  - However, a token remains reusable after `/api/reset-verify` succeeds. The same token can be submitted repeatedly from its bound session until a password update occurs.
  - This violates the explicit requirement that password reset tokens be single-use.

- **XSS and injection protections: PASS**
  - User-controlled values are not inserted through `innerHTML`.
  - Client messages use `textContent` and `createTextNode`.
  - Strict CSP with per-response nonces is configured.
  - No external or untrusted scripts are permitted.

- **Sensitive-route access control / IDOR resistance: PASS**
  - MFA and password-update routes require a valid session-bound recovery state.
  - Password update additionally requires successful MFA.
  - No route exposes account identifiers, folders, patient records, or similar private data.

- **Safe-authentication and anti-social-engineering guidance: PASS**
  - The UI explicitly warns users not to share passwords or verification codes and to use only the hospital address.

- **Production-safe failures and no debug/stack-trace disclosure: PASS**
  - Unknown routes return generic 404 responses.
  - Exceptions return a generic 500 response.
  - The server startup error does not disclose certificate paths, key material, or stack traces.

- **Code validity / direct Bun execution: PASS, conditional on certificate availability**
  - The TypeScript and Bun APIs used are compatible with direct Bun execution, including top-level `await`.
  - The server intentionally exits if `certs/cert.pem` and `certs/key.pem` are absent; this is consistent with the TLS-only requirement, provided those ready-made files are placed at the required paths.

## FAILING_ITEMS

- **Reset-token reuse after successful verification**
  - `POST /api/reset-verify` sets `record.boundSessionId` and `session.resetKey`, but does not mark the reset record as consumed.
  - Repeating the same valid request in the same session continues returning `200` and provides the MFA mock code again.
  - The reset record is only marked `used = true` after `POST /api/password-update`.
  - This does not satisfy the required single-use reset-token property.

- **Account recoverability can be enumerated through `testToken`**
  - `POST /api/reset-request` returns `{ message: generic, testToken: rawToken }` only when `identifier` matches `MOCK_ACCOUNT_IDENTIFIER`.
  - Invalid or unknown identifiers return only `{ message: generic }`.
  - Although the rendered message is generic, a caller can inspect the response body and determine whether the identifier is a recoverable account.
  - This conflicts with the privacy-preserving reset requirement and the requirement not to expose private identifiers/account existence.

## NEW_TASKS

1. **Consume reset tokens at successful token verification.**
   - On the first successful `/api/reset-verify`, mark the reset token as consumed immediately so later verification attempts with that token fail.
   - Create a separate short-lived, session-bound recovery authorization state for the MFA and password-update stages, rather than continuing to depend on an unconsumed reset token.

2. **Make reset-request responses and observable behavior non-enumerating.**
   - Ensure valid, invalid, and unknown identifiers return the same JSON shape, including a testing-safe simulated delivery value where required.
   - For unknown identifiers, use a non-actionable decoy recovery flow that cannot update a real account, while preserving generic responses through all stages.
   - Do not let the presence, absence, validity, or final outcome of a test token reveal whether a real recoverable account exists.

## DECISION

**FAIL**