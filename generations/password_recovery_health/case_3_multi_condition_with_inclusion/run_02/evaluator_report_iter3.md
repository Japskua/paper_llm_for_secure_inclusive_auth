## SUMMARY

The artifact is a well-structured single-file Bun application with a functional simulated recovery flow, TLS configuration, CSRF defenses, CSP nonces, Argon2id password hashing, MFA simulation, input validation, and accessible step-oriented UI. However, it does not fully satisfy the privacy/non-enumeration and pause-and-return inclusivity requirements. In particular, recovery-account existence can be inferred through API state and follow-up behavior, and expired recovery state can restore the user into an unusable step without clear recovery guidance.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun server and browser SPA**
  - The full server, HTML template, CSS, and vanilla browser JavaScript are contained in `app.ts`.
  - It uses `Bun.serve()` directly, without a bundler, framework, compilation step, or external assets.

- **PASS — TLS and secure response headers**
  - The Bun server is configured with `certs/cert.pem` and `certs/key.pem`.
  - Responses include HSTS, CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`, and cache-prevention headers.
  - The session cookie uses `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, and the valid `__Host-` prefix pattern.

- **PASS — CSRF protections for sensitive requests**
  - A cryptographically random CSRF token is generated per session.
  - All state-changing API routes call `validateSensitiveRequest`.
  - Requests require both an exact same-origin `Origin` header and a matching `X-CSRF-Token`.

- **PASS — Password reset token security**
  - Recovery tokens are generated with cryptographically secure random bytes.
  - Tokens are session-bound, expire after 15 minutes, are checked using constant-time comparison, are throttled after failed verification attempts, and are invalidated after password replacement.
  - Passwords are stored using `argon2id`, not plaintext.

- **PASS — Login and MFA protections**
  - Password login is throttled after repeated failures.
  - MFA codes have an expiry, failed-attempt throttling, and a separate completion step.
  - Protected privacy and appointment routes require an authenticated MFA-completed session.

- **PASS — XSS/injection handling**
  - User-facing browser output uses `textContent`, not unsafe HTML insertion.
  - Identifier validation restricts allowed characters.
  - Server-generated dynamic values embedded in HTML are generated internally and safely serialized.
  - CSP permits only nonce-authorized inline application code.

- **PASS — Recovery link and manual-code flow**
  - The simulated recovery link opens the verification stage.
  - The recovery code can also be pasted or typed manually.
  - Simulated recovery and MFA values are logged through browser-side `console.log`, as required for testing.

- **PASS — Internal navigation and appointment completion**
  - The flow supports request, code verification, password change, sign-in, MFA, privacy acceptance, and appointment confirmation.
  - Internal navigation buttons and the `#verify` recovery link behavior are implemented.

- **FAIL — Account registration status is inferable**
  - The UI says, “We will not say whether an account is registered,” but the API exposes account-dependent behavior.
  - After `/api/recovery/request`, `/api/state` returns `hasReset: true` for a known account and `hasReset: false` for an unknown account.
  - An attacker can submit an identifier and then call `/api/state` using the same session to determine whether that identifier belongs to a provisioned account.
  - The verification behavior also differs: a known account’s returned test token succeeds, while an unknown account’s returned decoy token produces “This recovery code is no longer available.”
  - This violates the stated privacy behavior and weakens resistance to account enumeration.

- **FAIL — Pause/return experience can restore into an unusable recovery step**
  - Reset tokens expire after 15 minutes, which is appropriate for security, but the client can restore `recoveryStage === "verified"` and open the password panel even after the reset authorization has expired.
  - In that case, password submission fails with “Please verify a current recovery code before changing your password,” forcing the user to manually navigate backward and start again.
  - The UI states “There is no rush” and “Progress remains in this browser session,” but it does not clearly explain the limited lifetime of the recovery authorization or automatically guide the user to request a new code when the state is no longer actionable.
  - This does not meet the requirement to let users pause and return without losing orientation or encountering unexpected task failure.

## FAILING_ITEMS

- **Recovery account enumeration through state and follow-up responses**
  - `publicState()` exposes `hasReset`, which directly reflects whether a valid account reset record was created.
  - `/api/recovery/verify` also distinguishes a retained valid token from an unknown-account decoy token.
  - This contradicts the UI promise that the portal will not reveal whether an account is registered.

- **Expired recovery state is not reconciled before UI restoration**
  - `/api/state` can report `recoveryStage: "verified"` after the corresponding reset record has expired.
  - The browser restoration logic prioritizes `recoveryStage === "verified"` and shows the password panel despite the server no longer allowing password replacement.
  - The user receives an error only after entering a new password, rather than clear guidance immediately upon return.

## NEW_TASKS

1. **Remove account-dependent recovery state disclosure and normalize recovery outcomes.**
   - Do not expose `hasReset` or any equivalent account-dependent signal through `/api/state`.
   - Ensure known and unknown identifiers receive indistinguishable recovery-request and recovery-verification responses.
   - Use a session-local decoy recovery state for unknown identifiers so that the visible flow does not reveal account existence, while ensuring decoy flows never authenticate a user, expose data, or create a real account.

2. **Normalize expired recovery state before returning `/api/state` and update the UI restoration flow.**
   - When a reset token has expired, clear or downgrade stale recovery stages such as `"verified"` to a state that requires a new recovery request.
   - Return a non-sensitive, user-friendly status indicating that a fresh recovery code is needed.
   - Update the browser startup restoration logic to route directly to the recovery request panel with clear feedback, rather than showing a password form that will inevitably fail.
   - Preserve non-secret orientation data, such as the entered identifier and progress explanation, while requiring a fresh short-lived security code.

## DECISION

FAIL