## SUMMARY

The artifact is a valid single-file Bun application with inline HTML/CSS/vanilla browser JavaScript, TLS configuration, CSP/security headers, session CSRF protection, random expiring reset tokens, password hashing, throttling, and an accessible guided recovery UI. However, it has a critical authorization flaw: any visitor can initiate a recovery flow using any syntactically valid identifier and receive a usable reset token, allowing them to reset the shared demo account password and complete MFA without proving ownership of an account. This fails the password-reset authorization and access-control requirements.

## FUNCTIONAL_CHECK

- **Single-file `app.ts` implementation with Bun server, HTML, CSS, and vanilla client JS — PASS**
  - The entire artifact is contained in one `app.ts`.
  - It uses `Bun.serve`, inline template HTML, inline nonce-protected CSS, and vanilla browser JavaScript.
  - No frameworks, bundlers, compilation pipeline, external assets, or external network calls are used.

- **Bun TLS server uses the required certificate paths — PASS**
  - The server is configured with:
    - `cert: Bun.file("certs/cert.pem")`
    - `key: Bun.file("certs/key.pem")`
  - The server rejects requests whose URL is not HTTPS.

- **Guided, low-stress recovery UX with progress, help, and saved progress — PASS**
  - The UI provides numbered visible progress steps.
  - Language is generally clear and structured.
  - Help and safety guidance is available on every step.
  - The selected step is persisted in `localStorage`, allowing users to return without losing overall position.
  - There are no countdown timers or unexpected redirects.

- **Recovery code can be manually submitted and mock delivery is available in browser console/UI — PASS**
  - `/api/recovery/initiate` returns `mockToken`.
  - The browser logs the token with `console.log(...)` through `audit(...)`.
  - The token is also shown in the visible practice log.
  - The verification screen supports manual token entry and a simulated-link continuation action.

- **CSRF protection on state-changing requests — PASS**
  - A random CSRF value is generated per server session.
  - All POST API routes require `x-csrf-token` or body CSRF validation.
  - The session cookie is `HttpOnly`, `Secure`, `SameSite=Strict`, and has an opaque random value.

- **XSS and unsafe output handling — PASS**
  - User-supplied values are not rendered back into the DOM.
  - DOM construction uses `textContent` rather than dangerous HTML insertion.
  - Inputs are constrained and normalized where needed.
  - CSP uses per-response nonces and does not allow unrestricted inline scripts.
  - No external script sources are permitted.

- **Security headers and production error handling — PASS**
  - HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and no-cache headers are included.
  - Generic error responses avoid stack traces and debug output.

- **Reset token randomness, expiration, session binding, and single-use behavior — PASS**
  - Reset tokens use cryptographically secure random bytes.
  - Tokens are stored as SHA-256 hashes.
  - Tokens expire after 10 minutes.
  - Tokens are bound to the current server session.
  - Tokens are marked used after a successful password reset.

- **Password policy and password hashing — PASS**
  - Passwords require 12–128 characters with uppercase, lowercase, number, and symbol.
  - Passwords are hashed with Bun bcrypt before storage.
  - Plaintext passwords are not stored in server state.

- **Brute-force protections for login, recovery-code verification, and MFA — PASS**
  - Login attempts are rate-limited and locked after repeated failures.
  - Recovery verification attempts are limited and lock after five failures.
  - MFA attempts are likewise limited and locked.

- **MFA implementation and simulated browser delivery — PASS**
  - MFA is required after password reset and sign-in.
  - The deterministic mock MFA code is returned to the browser and logged there, matching the simulation requirement.
  - MFA state expires and has attempt limits.

- **Password reset prevents unauthorized account access — FAIL**
  - `/api/recovery/initiate` accepts any syntactically valid identifier and always creates a reset token for the active session.
  - The identifier is never checked against an account or used to bind the reset request to an account.
  - Any visitor can submit an arbitrary valid identifier, receive `mockToken`, verify it, set a new password, pass the deterministic MFA code, and become authenticated.
  - This violates the requirements that password reset prevent unauthorized access and that sensitive routes enforce proper access control.

- **Sensitive UI states cannot be falsely accessed through client-side navigation — FAIL**
  - The `hashchange` handler accepts all allowed client states, including `#privacy`, `#appointment`, and `#complete`.
  - An unauthenticated visitor can manually navigate to `#complete` and be shown “Request confirmed,” even though no appointment was confirmed server-side.
  - Server-side API authorization prevents actual protected actions, but the UI gives misleading completion/status feedback and does not consistently restore state from server authorization.

- **Internal flow navigation and protected actions — PARTIAL / FAIL**
  - Server-side protected actions for privacy acceptance and appointment confirmation are correctly guarded.
  - However, direct hash navigation can display protected or completed screens without the corresponding authorized server state, so the complete flow state is not reliably represented.

## FAILING_ITEMS

- **Critical: Recovery initiation is not tied to a real account or verified ownership channel.**
  - Any valid-looking identifier produces a working reset token.
  - The reset token permits changing the global `accountPasswordHash`.
  - This enables unauthorized password reset and authentication.

- **Critical: Password reset modifies a globally shared account password without an account binding.**
  - `accountPasswordHash` is a single global variable.
  - `Recovery` contains no account identifier or account reference.
  - A recovery request for arbitrary input can change the password for the only login account.

- **Moderate: Client-side hash navigation can display unauthorized protected/completed states.**
  - `window.addEventListener("hashchange", ...)` permits transitions to `privacy`, `appointment`, and `complete` without checking server session state.
  - This can falsely tell a user that an appointment was confirmed.

- **Moderate: The initial server-state restoration logic is bypassed by the hash-change behavior.**
  - `start()` only permits a limited safe hash override, but later hash changes accept every state in `allowed`.
  - The application should use one authorization-aware route resolver for both startup and hash navigation.

## NEW_TASKS

1. **Bind recovery requests to an account record and only issue a reset token for the intended account.**
   - Replace the global `accountPasswordHash` model with an internal account record keyed by a non-disclosed account identifier.
   - Store an internal account reference in `Recovery`, not the user-provided identifier itself.
   - Preserve non-enumerating responses: return the same generic message whether the identifier exists or not.

2. **Prevent arbitrary identifiers from receiving usable reset tokens in the simulation.**
   - For unknown identifiers, return the generic recovery response but do not create a usable recovery token.
   - For the designated simulated account, create the token and return/log the mock token only for that account’s simulated delivery path.
   - Ensure reset verification requires a recovery record bound to an actual account.

3. **Update password reset to modify only the account bound to the verified recovery record.**
   - On `/api/recovery/reset`, retrieve the account from `recovery.accountId`.
   - Hash and store the password only on that account.
   - Reject reset attempts where no valid, verified, account-bound recovery exists.

4. **Make client-side route transitions authorization-aware.**
   - Replace unrestricted `hashchange` state assignment with a route validation function that checks current server session state.
   - Redirect unauthorized `privacy`, `appointment`, and `complete` route requests to the appropriate valid step, such as `home`, `mfa`, or `privacy`.

5. **Prevent false confirmation UI.**
   - Render the completion screen only when `appointmentConfirmed` is true in the current server session.
   - On direct navigation to `#complete` without confirmation, show an explanatory message and return the user to the authorized next step.

## DECISION

FAIL