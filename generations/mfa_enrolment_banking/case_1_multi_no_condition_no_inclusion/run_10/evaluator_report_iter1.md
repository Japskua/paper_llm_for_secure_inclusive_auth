## SUMMARY

The artifact is a well-structured single-file Bun HTTPS SPA with strong coverage of session handling, CSRF, TLS, headers, input validation, encryption, and the MFA enrolment UI. However, it contains a critical missing API endpoint that prevents recovery codes from ever being displayed, breaking completion of the enrolment flow. It also retains backup-code plaintext in server session memory and has a refresh-state failure during authenticator provisioning.

## FUNCTIONAL_CHECK

- **Single file `app.ts` containing Bun server, HTML, CSS, and vanilla browser JS — PASS**
  - The supplied artifact is contained in one TypeScript file, embeds the complete HTML/CSS/JS page, and uses `Bun.serve`.

- **No frameworks, build tools, external network calls, or external UI assets — PASS**
  - The app uses regular HTML, inline CSS, vanilla JavaScript, Bun APIs, and Node/Bun built-ins only.
  - The TLS certificate files are required server configuration assets, not UI/runtime external network assets.

- **HTTPS/TLS using supplied certificate paths — PASS**
  - `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`.
  - The server exposes only a TLS listener and includes HSTS.

- **Mobile-responsive, legible SPA UI — PASS**
  - The page uses a constrained mobile-friendly layout, responsive sizing, accessible labels, suitable input types, and touch-sized buttons.

- **Identity verification flow works — PASS**
  - Sign-in validates email and phone values.
  - A session is rotated at sign-in.
  - A mock identity OTP is generated, returned to the protected browser UI, logged through browser-side `console.log`, time-limited, single-use, and rate-limited.

- **Authenticator provisioning and manual setup flow works during a non-refreshed session — PASS**
  - The app displays a manual secret and provisioning URI.
  - The secret can be submitted manually alongside a TOTP.
  - The server encrypts the secret using AES-GCM and validates the generated TOTP.

- **Recovery-code display and enrolment completion flow — FAIL**
  - The browser calls `GET /api/recovery-codes` after authenticator confirmation.
  - No `/api/recovery-codes` route exists in `handleApi`.
  - The request falls through to `if (request.method !== "POST") return genericError(404, request)`.
  - As a result, recovery codes are never displayed and the user cannot finish the required recovery-code storage stage.

- **Recovery-code regeneration flow — FAIL**
  - Recovery-code verification and regeneration server routes exist, but the initial recovery-code UI cannot load because `/api/recovery-codes` is missing.
  - Therefore, the full recovery-code lifecycle is not functional.

- **Server-side authorization / IDOR protection — PASS**
  - API state is derived from an opaque server-side session cookie rather than client-provided user identifiers.
  - MFA settings, provisioning, confirmation, recovery verification, regeneration, and logout require a valid session and appropriate stage.
  - No endpoint accepts a mutable account ID or user ID that could be manipulated for IDOR.

- **CSRF protection on state-changing actions — PASS**
  - State-changing POST routes require a server-issued CSRF token validated with constant-time comparison.
  - Cookies use `SameSite=Strict`.

- **Secure session cookie configuration — PASS**
  - The session cookie includes `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, and an expiry.
  - Session IDs are generated with cryptographically secure randomness.
  - Sessions enforce idle and absolute expiration and are deleted on logout.

- **Security response headers and CORS restriction — PASS**
  - CSP, HSTS, `X-Content-Type-Options`, `X-Frame-Options`, `frame-ancestors 'none'`, Referrer-Policy, and Permissions-Policy are set.
  - CORS only permits fixed local TLS origins.

- **No server-side secret logging or verbose errors — PASS**
  - Server code does not log OTPs, seeds, recovery codes, or session values.
  - Error responses are generic and caught exceptions return generic content without stack traces.

- **Secret and recovery-code cryptographic handling — FAIL**
  - The authenticator secret is encrypted at rest using AES-GCM, which is correct.
  - Recovery codes are hashed with SHA-256 plus a server-side pepper, which is appropriate for verification.
  - However, `session.recoveryDisplay` stores plaintext recovery codes in the server-side `Session` object indefinitely:
    - `session.recoveryDisplay = plaintext;`
  - This conflicts with the requirement to store backup codes using strong hashing/encryption at rest and with the UI statement that recovery codes “are not displayed again.”

- **Single-use, time-bound verification and rate limiting — PASS**
  - Identity OTPs are time-bound and marked used.
  - Authenticator confirmation is marked used for the provisioning flow.
  - Recovery codes are removed after successful use.
  - Failed attempts lock after five failures for ten minutes.

- **No browser persistence of secrets or session tokens — PASS**
  - The browser client does not use `localStorage` or `sessionStorage`.
  - The session cookie is HttpOnly.
  - The UI only holds setup/recovery values in transient DOM and JavaScript state.

- **Internal navigation and refresh resilience — FAIL**
  - The “Back to MFA settings” and button-driven in-page navigation work.
  - However, if the browser is refreshed after `/api/authenticator/provision` has advanced the session to `"provisioned"`, bootstrap returns the `"setup"` view but does not restore the provisioning detail/secret.
  - The client displays the “Create authenticator setup” button, but clicking it calls provisioning again and the server rejects it because the stage is no longer `"verified"`.
  - The user cannot complete enrolment after a refresh at that stage.

## FAILING_ITEMS

- `GET /api/recovery-codes` is called by `loadRecoveryCodes()` but is not implemented on the server. This is a blocking functional defect that prevents recovery code display and completion of MFA enrolment.

- Plaintext recovery codes are retained in `session.recoveryDisplay` after generation. This violates the intended one-time-display model and weakens the requirement that backup codes be stored as protected hashed/encrypted values.

- The `"provisioned"` session state is not recoverable after a page refresh. Bootstrap routes the user to setup, but the client cannot retrieve the existing manual secret/provisioning URI or safely restart provisioning.

- The recovery-code “shown once” requirement is not enforced in the server state design. Even after an endpoint is added, retaining `recoveryDisplay` would permit repeated retrieval unless it is explicitly consumed and cleared.

## NEW_TASKS

1. Implement an authenticated `GET /api/recovery-codes` endpoint that permits only `session.stage === "mfa"` and returns the just-generated recovery codes exactly once for the current account session.

2. Replace persistent plaintext `session.recoveryDisplay` storage with a one-time protected display mechanism:
   - retain recovery codes only long enough to return them once;
   - clear the plaintext values immediately after successful retrieval;
   - retain only the salted/peppered hashes for future recovery-code verification.

3. Update `setRecoveryCodes()` and the recovery-code retrieval endpoint so regenerated codes also follow the same one-time display behavior.

4. Make the `"provisioned"` bootstrap state resumable after refresh:
   - either provide an authenticated endpoint that returns the current provisioning secret/URI only while setup is pending, or
   - allow a secure replacement provisioning operation that invalidates the prior pending secret and generates a new one.
   - Update browser bootstrap logic to render the corresponding usable setup state.

5. Verify the complete browser flow end-to-end: sign in, identity verification, provisioning, authenticator confirmation, initial recovery-code display, finish, recovery-code verification, regeneration, replacement-code display, logout, and refresh during pending provisioning.

## DECISION

FAIL