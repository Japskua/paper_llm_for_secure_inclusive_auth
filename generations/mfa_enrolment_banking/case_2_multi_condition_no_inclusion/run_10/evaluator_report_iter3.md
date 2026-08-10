## SUMMARY

The artifact is a valid single-file Bun HTTPS SPA with a responsive mobile UI, working simulated identity/TOTP/recovery-code flows, secure headers, encrypted OTP-secret storage, hashed recovery codes, session rotation, CSRF protection for authenticated mutations, and browser-only mock secret logging. However, it does not fully meet the verification lockout and anti-enumeration timing requirements: failed identity verification attempts for unknown account details can be reset by creating a new pre-authentication session, and account-detail comparisons short-circuit in a timing-observable way.

## FUNCTIONAL_CHECK

- **Single `app.ts` Bun server with inline HTML, CSS, and vanilla browser JavaScript — PASS**
  - The server, HTML template, styles, and browser logic are all in the supplied `app.ts`.
  - No framework, bundler, compilation step, external JavaScript, or external asset is used.

- **TLS/HTTPS enforcement using `certs/cert.pem` and `certs/key.pem` — PASS**
  - Startup checks that both certificate files exist.
  - `Bun.serve` is configured with `tls: { cert, key }`.
  - The server does not expose a separate HTTP listener.

- **Mobile-responsive, legible, semantic MFA UI — PASS**
  - Includes responsive width constraints, mobile viewport metadata, accessible labels, large input/button targets, focus styling, and a narrow-screen media query.
  - The UI presents identity verification, authenticator setup, manual setup-secret entry, backup code display, recovery-code verification, regeneration, and logout.

- **Manual authenticator provisioning and simulated verification work — PASS**
  - The setup secret is shown in the UI for manual authenticator entry.
  - A current test TOTP is returned by the server and logged in the browser.
  - TOTP verification is time-windowed and prevents reuse of accepted counters.

- **Mock OTP and recovery-code values are logged in the browser — PASS**
  - Client-side `log()` calls `console.log`.
  - Identity codes, TOTP test values, generated recovery codes, and regenerated recovery codes are displayed in the visible log panel and written to the browser console.
  - The server does not log secrets.

- **Server-side MFA authorization and IDOR prevention — PASS**
  - MFA endpoints derive ownership from the HttpOnly session through `owner(request)`.
  - The only accepted authenticated owner is `ACCOUNT.id`.
  - State-changing MFA endpoints reject submitted `userId`, `accountId`, `ownerId`, and, where applicable, `email` fields through `manipulated()`.

- **CSRF protection for authenticated MFA state changes — PASS**
  - MFA setup, confirmation, recovery-code use, recovery-code regeneration, and logout require the per-session `X-CSRF-Token`.
  - The session cookie is `SameSite=Strict`, providing an additional CSRF defense.

- **Secure response headers and restrictive CORS — PASS**
  - Responses include CSP with nonce-based inline script/style permission, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, `Permissions-Policy`, and `Cache-Control: no-store`.
  - CORS is only emitted for trusted localhost HTTPS origins.

- **Secure session handling — PASS**
  - Session cookies are `HttpOnly`, `Secure`, `SameSite=Strict`, and use a compliant `__Host-` prefix configuration.
  - Authentication rotates the session identifier.
  - Idle and absolute timeouts are enforced server-side.
  - Logout invalidates the server session and expires the cookie.

- **Secret and backup-code protection at rest — PASS**
  - OTP seeds are AES-GCM encrypted before being retained in enrollment/MFA records.
  - Recovery codes are stored as keyed HMAC-SHA-256 values, not plaintext.
  - Secure random generation is used for session tokens, CSRF tokens, OTP setup secrets, identity codes, and recovery codes.

- **Input validation and output encoding — PASS**
  - Email, phone, OTP, and backup-code formats are validated server-side.
  - JSON size and content type are constrained.
  - Dynamic UI values are inserted with `textContent`, not interpolated into HTML.
  - Generic errors avoid reflecting untrusted values.

- **Single-use, time-bound verification codes — PASS**
  - Identity codes expire after `VERIFY_WINDOW_MS` and become invalid once the session is rotated after authentication.
  - TOTP accepts current/previous time steps only and records accepted counters to prevent reuse.
  - Recovery codes are deleted after successful use.

- **Rate limiting and lockout for repeated failed verification attempts — FAIL**
  - Authenticator and recovery-code verification attempts are persistently throttled.
  - Identity verification attempts for valid account details are throttled by `account:${ACCOUNT.id}`.
  - However, identity verification attempts for unknown details are throttled using `details:unverified-session:${session.id}`. A caller can start a new pre-auth session through `/api/auth/start` after five failed attempts and immediately continue guessing, bypassing the intended persistent lockout.
  - The existing `identityThrottleKey(email, phone)` helper appears intended to solve this but is never used.

- **Avoid account/user enumeration through response timing — FAIL**
  - In `/api/auth/start`, the account check is:
    ```ts
    const known = secureEquals(email, ACCOUNT.email) && secureEquals(phone, ACCOUNT.phone);
    ```
  - JavaScript `&&` short-circuits. When the email does not match, the phone comparison is skipped; when the email does match, it is performed. This creates different comparison work and can make account-detail matching timing-observable.
  - The response body is generic, but the requirement also explicitly requires avoiding enumeration through timing.

## FAILING_ITEMS

- **Identity-verification lockout is bypassable for unrecognized account details.**
  - `/api/auth/verify` uses a per-session throttle key for unverified sessions:
    ```ts
    `details:unverified-session:${session.id}`
    ```
  - A new `/api/auth/start` request creates a new session ID and therefore a fresh attempt budget.
  - This conflicts with the intended durable-throttle behavior described in the source comments and fails the repeated-failed-verification lockout requirement.

- **Account matching in `/api/auth/start` has a short-circuit timing difference.**
  - The `&&` expression only evaluates the phone comparison when the email comparison succeeds.
  - The application must perform equivalent comparison work regardless of whether the submitted email matches, then combine the results afterward.

## NEW_TASKS

1. **Persist the identity-verification throttle key across newly created pre-auth sessions.**
   - Add an `identityThrottleKey` field to `Session`.
   - In `/api/auth/start`, derive and store the key using `identityThrottleKey(email, phone)`.
   - In `/api/auth/verify`, use `session.identityThrottleKey` instead of `details:unverified-session:${session.id}`.
   - Ensure repeated attempts using the same submitted details remain locked after a new `/api/auth/start` request until `LOCK_MS` has elapsed.

2. **Remove short-circuit behavior from account-detail matching.**
   - In `/api/auth/start`, evaluate email and phone comparisons independently:
     ```ts
     const emailMatches = secureEquals(email, ACCOUNT.email);
     const phoneMatches = secureEquals(phone, ACCOUNT.phone);
     const known = emailMatches && phoneMatches;
     ```
   - Do not conditionally skip one comparison based on the other comparison’s result.

## DECISION

**FAIL**