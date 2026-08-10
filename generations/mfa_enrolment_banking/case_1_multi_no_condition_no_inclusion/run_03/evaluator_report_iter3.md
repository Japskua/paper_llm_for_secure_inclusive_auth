## SUMMARY

The artifact is a single-file Bun HTTPS SPA with a responsive MFA enrolment UI and substantial security controls: opaque HttpOnly/Secure/SameSite cookies, server-side session ownership, CSRF tokens, restrictive headers, encrypted TOTP secrets, PBKDF2 recovery-code verifiers, validation, generic errors, and deterministic browser-visible test fixtures. However, it has security/functional flaws that prevent acceptance: concurrent verification requests can consume a supposedly single-use code more than once, and the provisioning endpoint can overwrite an already enabled MFA record and thereby disable MFA.

## FUNCTIONAL_CHECK

- **Single `app.ts` Bun server with inline HTML, CSS, and vanilla browser JavaScript — PASS**  
  The server, UI template, styling, and browser-side interactivity are all contained in `app.ts`. No framework, external asset, bundler, or external network call is used.

- **HTTPS/TLS using the supplied certificate paths — PASS**  
  `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`.

- **Responsive, legible mobile web UI — PASS**  
  The document includes a mobile viewport meta tag, a constrained mobile-first layout, usable input/button sizing, and a narrow-screen media query.

- **Functional enrolment flow: sign-in, identity verification, authenticator setup, recovery-code display/acknowledgement — PASS**  
  The UI routes through sign-in, identity verification, provisioning, OTP confirmation, recovery-code display, acknowledgement, dashboard, regeneration, recovery-code verification, and logout. Client actions call corresponding server endpoints.

- **Mocks are exposed only in the browser UI/browser console for test use — PASS**  
  Identity code, TOTP fixture, provisioning secret, and recovery codes are returned in explicit test mode and logged by browser-side `console.log` through `testLog`. The server does not log those secret fixtures.

- **Manual entry is available for authenticator material — PASS**  
  The provisioning UI displays a manual secret and deterministic TOTP fixture, and provides an OTP input for confirmation.

- **Server-side authorization and IDOR resistance — PASS**  
  MFA state is derived exclusively from the opaque session cookie’s server-side `userId`; endpoints do not accept a client-controlled target user/account identifier.

- **CSRF protection for authenticated MFA state-changing endpoints — PASS**  
  MFA confirmation, provisioning, recovery regeneration, recovery verification, acknowledgement, and logout require a per-session CSRF token and reject untrusted `Origin` values. The session cookie also uses `SameSite=Strict`.

- **Security headers and CORS restriction — PASS**  
  Responses include CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, and trusted-origin-only CORS headers.

- **Secure session management — PASS**  
  Session cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`; sessions have idle and absolute expiry; the session identifier and CSRF token are replaced after successful identity verification; logout invalidates the session and expires the cookie.

- **Secure at-rest handling and generation of MFA material — PASS**  
  TOTP secrets are generated with `crypto.getRandomValues` and AES-GCM encrypted. Recovery codes are generated cryptographically and stored as salted PBKDF2 verifiers rather than plaintext.

- **Input validation and output safety — PASS**  
  JSON bodies are restricted to endpoint-specific allowed keys; email, phone, OTP, and recovery-code formats are validated; user-controlled strings are not interpolated into HTML.

- **Time-bound verification values and failed-attempt lockout — FAIL**  
  Expiry and failure counters are implemented, but single-use enforcement is not atomic. Concurrent requests can successfully verify the same identity code or authenticator OTP more than once.

- **MFA cannot be silently disabled/replaced through enrolment endpoints — FAIL**  
  `POST /api/mfa/provision` unconditionally replaces the existing MFA record, including an enabled record, with a new `enabled: false` record. An authenticated user can therefore call this endpoint directly and disable established MFA without a dedicated reset/re-authentication flow.

## FAILING_ITEMS

- **Concurrent identity-code verification can succeed more than once.**  
  In `verifyIdentity`, `challenge.identityUsed` is checked before `await matchesHash(...)`, then set only after the await completes. Two simultaneous requests with the same valid session, CSRF token, and identity code can both observe `identityUsed === false`, both pass validation, and both create authenticated sessions.

- **Concurrent authenticator confirmation can succeed more than once.**  
  In `confirmAuthenticator`, the record remains `enabled === false` while asynchronous decryption/TOTP computation occurs. Parallel valid confirmation requests can both pass the `!mfa.enabled` check and each issue a distinct set of recovery codes. This violates the requirement that OTP verification is single-use.

- **`/api/mfa/provision` can disable existing enabled MFA.**  
  The endpoint performs `mfaByUser.set(session.userId, { ..., enabled: false, ... })` without checking whether MFA is already enabled. Since the endpoint is callable directly by any verified session, it overwrites active MFA state and invalidates/replaces recovery-code protection without an explicit reset operation.

## NEW_TASKS

1. **Make identity-code consumption atomic.**  
   After the asynchronous hash comparison completes, synchronously re-check `identityUsed` and the challenge expiry/lock state, then set `identityUsed = true` before any further asynchronous work or response construction. Ensure all concurrent loser requests receive a generic failure response.

2. **Make authenticator OTP confirmation atomic and single-use.**  
   Compute/validate the OTP, then synchronously re-read and verify that the stored MFA record is still pending and not enabled. Atomically transition it out of the pending state before permitting another await or issuing recovery codes. Ensure concurrent duplicate confirmations fail and cannot create multiple recovery-code sets.

3. **Prevent provisioning from overwriting enabled MFA.**  
   Change `/api/mfa/provision` to reject requests when `mfaByUser.get(session.userId)?.enabled` is true. If authenticator replacement is intended, implement a separate explicitly named reset/re-enrolment endpoint requiring an appropriate step-up verification and clear user confirmation before replacing active MFA material.

## DECISION

FAIL