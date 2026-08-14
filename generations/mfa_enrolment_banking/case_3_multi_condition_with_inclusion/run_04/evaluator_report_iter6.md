## SUMMARY

The artifact is a single-file Bun/TypeScript SPA with a largely functional MFA enrolment flow, HTTPS configuration, server-side session ownership checks, CSRF headers, encrypted pending OTP secrets, hashed recovery codes, rate limits, and accessible mobile-oriented styling. However, it does not fully meet the inclusivity and security requirements: it lacks a QR-code setup option, exposes test OTPs and OTP secrets through API responses and browser console logging outside explicit test mode, and cannot correctly resume an in-progress MFA setup after a page refresh. Therefore, it cannot be accepted as-is.

## FUNCTIONAL_CHECK

- **Single `app.ts` containing Bun server, HTML, CSS, and browser JavaScript — PASS**
  - The entire application is contained in one file.
  - No framework, bundler, compiler pipeline, external asset, or external network call is used.

- **Bun HTTPS server using the supplied certificate paths — PASS**
  - The server reads `certs/cert.pem` and `certs/key.pem`.
  - `Bun.serve` is configured with `tls: { cert, key }`.

- **Responsive mobile web UI with readable layout — PASS**
  - The app uses a constrained responsive layout, mobile viewport meta tag, readable font sizes, generous spacing, clear form controls, and visible focus styling.
  - The CSS avoids italics and uses plain, legible text.

- **Dyslexia-friendly plain language, examples, hints, and non-timed flow — PASS**
  - Instructions are generally short and plain.
  - Code and email examples are supplied.
  - Helpful hints are present across key steps.
  - There are no moving/flashing elements or reading countdowns.

- **One prominent primary action per step — PASS**
  - Sign-in, identity verification, authenticator confirmation, backup-code creation, and final completion each have a clear main action.
  - Secondary actions are visually differentiated.

- **Identity-code simulation and verification — PASS**
  - The server generates an identity verification code, applies expiry, single-use handling, failure counting, and lockout.
  - The browser logs the simulated code for testing.
  - Re-requesting an identity code invalidates the previous code.

- **Authenticator provisioning and verification — PARTIAL / FAIL**
  - The server generates a Base32 secret, creates an `otpauth://` provisioning URI, encrypts the secret at rest in session memory, and validates time-based TOTP values.
  - Manual secret display and copy-to-clipboard are supported.
  - However, the UI does **not provide a QR code option**, despite the requirement to offer QR-code options.

- **Manual authenticator setup support — PASS**
  - The provisioning URI can be copied.
  - The Base32 secret can be revealed and copied for manual entry in an authenticator app.

- **Recovery-code generation, display, copy, download, regeneration, and one-time use — PASS**
  - Recovery codes are generated with cryptographic randomness outside test mode.
  - Codes are hashed before storage.
  - The UI supports reveal/hide, copy, download, regeneration, and verification of a one-time recovery code.
  - Used recovery-code hashes are removed.

- **Retry and re-request UX without penalty — FAIL**
  - Identity and authenticator failure counters are not reset when new identity codes or new authenticator setup details are requested.
  - A user who made failed attempts can still be locked out even after explicitly requesting a replacement setup/code, contrary to the “retry/re-request … without penalty” UX expectation.

- **In-progress flow survives browser refresh/navigation — FAIL**
  - If the user refreshes while their session is at stage `"mfa"` but before authenticator verification is complete, the client always renders the identity-code screen.
  - The server rejects identity verification for an `"mfa"` session, leaving the user unable to resume the flow.
  - The server has pending authenticator state, but `/api/session` does not return enough state for the client to restore the correct screen.

- **Internal flow navigation works — PARTIAL / FAIL**
  - Normal button-driven SPA transitions work.
  - Refreshing in the middle of enrolment breaks the flow, so the SPA’s state navigation is not robust.

- **Server-side authorization / IDOR prevention — PASS**
  - MFA management endpoints require an authenticated `"mfa"` session whose `userId` matches the server-owned account.
  - No client-submitted user ID is trusted.
  - Manipulated or guessed user IDs cannot be used to access another account’s MFA state.

- **CSRF protection for state-changing endpoints — PASS**
  - State-changing routes require the server-generated `x-csrf-token`.
  - Session cookies use `SameSite=Strict`.
  - A fresh session and CSRF token are issued after sign-in to reduce session fixation risk.

- **Secure session cookie settings — PASS**
  - Session cookies are set with `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, and `Max-Age`.
  - Sessions have idle and absolute expiry checks.
  - Sessions are invalidated on logout.
  - Session IDs are rotated after successful sign-in.

- **Secure headers and restricted CORS — PASS**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, Referrer Policy, and Permissions Policy are present.
  - CORS is allow-listed to localhost HTTPS origins only.
  - Requests with untrusted `Origin` headers are rejected.

- **No verbose server errors — PASS**
  - Server exceptions are caught and return a generic error response.
  - Internal stack traces are not returned to clients.

- **Secure random values and at-rest secret handling — PASS**
  - Session IDs, CSRF tokens, normal OTP values, OTP secrets, and recovery codes use `crypto.getRandomValues`.
  - Pending/enrolled authenticator secrets are AES-GCM encrypted in server session memory.
  - Recovery codes are stored as hashes, not plaintext.

- **No exposure of OTP seeds, OTPs, backup codes, or session tokens in logs — FAIL**
  - `/api/sign-in` returns `testCode` on every successful sign-in, including when `TEST_MODE` is false.
  - `/api/identity/send` also returns `testCode` outside test mode.
  - The browser unconditionally runs `console.log` for identity OTPs, authenticator secrets, provisioning URIs, and recovery codes.
  - This directly violates the requirement that OTP seeds, OTPs, and backup codes must not be exposed in logs outside an explicitly isolated test-only configuration.

- **Deterministic mocks restricted to test mode — FAIL**
  - Although deterministic generation is guarded by `TEST_MODE`, the sensitive test values are still returned to the browser and console-logged in non-test mode.
  - The code comments call these “test-only” fixtures, but the client-side `test(...)` helper is not guarded by `TEST_MODE`.

- **Server-side input validation and output encoding — PASS**
  - Inputs are type-checked, trimmed, length-limited, and format-validated for OTP and recovery-code routes.
  - No SQL/database layer exists, so prepared-query requirements are not applicable to this implementation.
  - Dynamic sensitive strings are inserted through `textContent`, not HTML interpolation, in the client UI.

- **Rate limiting, expiry, single-use codes, and lockouts — PASS**
  - Identity codes are time-bound and single-use.
  - TOTP setup expires.
  - Identity, authenticator, and recovery-code attempts are rate-limited and temporarily locked after repeated failures.

- **Browser storage restrictions — PASS**
  - The application does not use `localStorage`, `sessionStorage`, or non-HttpOnly cookies for secrets or session tokens.

## FAILING_ITEMS

- The authenticator setup flow does not provide a QR code, despite the explicit requirement to offer a QR-code option.
- Sensitive simulated credentials are exposed outside test mode:
  - Identity OTPs are returned in API JSON as `testCode`.
  - Identity OTPs, OTP secrets, provisioning URIs, and recovery codes are unconditionally sent to `console.log` in the browser.
- The code’s “test-only” logging is not actually restricted to `MFA_TEST_MODE=true` and non-production operation.
- Refreshing during the authenticator setup phase renders the identity verification screen even though the server session is already at `"mfa"` stage; the user cannot continue.
- Requesting a replacement identity code or a new authenticator setup does not reset relevant failed-attempt counters, which makes retry/re-request behavior punitive and inconsistent with the stated UX requirement.

## NEW_TASKS

1. Add a QR-code rendering option to the authenticator setup screen using locally implemented, inline JavaScript/HTML only; do not fetch external QR libraries or assets. Keep the provisioning URI and manual Base32 secret options available.

2. Restrict all mock credential disclosure to explicit non-production test mode:
   - Return `testCode`, fixture OTPs, fixture secrets, and fixture recovery codes only when `TEST_MODE` is enabled.
   - Expose a non-sensitive `testMode` flag to the client.
   - Guard every browser `console.log` of OTPs, secrets, provisioning URIs, and recovery codes behind that flag.
   - Do not emit these values in normal-mode API responses or browser logs.

3. Add resumable enrolment state:
   - Return safe progress information from `/api/session`, such as whether authenticator setup is pending and whether MFA is enabled.
   - Update client initialization to render the authenticator-start or authenticator-details step when the server session is already in `"mfa"` stage but enrolment is incomplete.
   - Ensure refreshes at every supported enrolment stage lead to a functional screen.

4. Define and implement retry behavior for replacement codes/setup details:
   - Reset identity failure state when issuing a new identity code, or otherwise clearly preserve the rate-limit policy while satisfying the retry UX.
   - Reset pending authenticator setup failure state when generating a genuinely new setup secret, unless a lockout is intentionally active.
   - Keep abuse protections and lockout behavior for repeated invalid attempts.

## DECISION

FAIL