## SUMMARY

The artifact is a single-file Bun HTTPS SPA with strong baseline controls: CSP/HSTS/clickjacking headers, Secure HttpOnly SameSite session cookies, CSRF tokens, session rotation, input validation, encrypted TOTP draft storage, hashed recovery codes, and a responsive mobile UI. However, it has race conditions that can violate recovery-code single-use behavior and can return provisioning/recovery-code results that are immediately invalidated by concurrent requests. It also visibly prints secrets and codes into an in-page “Logs” panel.

## FUNCTIONAL_CHECK

- **PASS — Single-file, zero-build implementation**
  - The server, HTML, CSS, and vanilla browser JavaScript are all contained in `app.ts`.
  - It uses `Bun.serve` directly and has no framework, bundler, external asset, external API, or database dependency.

- **PASS — HTTPS/TLS and secure response configuration**
  - Bun is configured with `certs/cert.pem` and `certs/key.pem`.
  - Responses include CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, referrer policy, and permissions policy.
  - Generic errors are returned without stack traces.

- **PASS — Session security**
  - Session cookies use `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, and the valid `__Host-` naming convention.
  - Sessions have idle and absolute timeouts.
  - The session ID is rotated after sign-in and identity verification.
  - Logout deletes the server-side session and clears the cookie.

- **PASS — Authorization and IDOR protections**
  - MFA provisioning, MFA confirmation, recovery-code verification, and recovery-code regeneration require an authenticated session for the fixed account owner.
  - The server ignores client-supplied ownership identifiers and rejects bodies containing likely identifier fields such as `userId`, `accountId`, or `ownerId`.
  - There is no client-selectable user/account identifier used to access MFA data.

- **PASS — CSRF and origin protections**
  - State-changing requests require a per-session CSRF token.
  - Session cookies are `SameSite=Strict`.
  - CORS is only enabled for explicit trusted localhost HTTPS origins.
  - Untrusted `Origin` values are rejected for API requests.

- **PASS — Input validation and output safety**
  - Server-side validators exist for email, phone, OTP, setup secrets, and recovery codes.
  - The UI does not inject server/user-controlled values with unsafe HTML interpolation; recovery codes are inserted with `textContent`.
  - No redirect functionality exists, so there is no open-redirect path.

- **PASS — TOTP and identity verification behavior**
  - Identity codes are cryptographically generated, expire after three minutes, and are invalidated by session rotation on successful verification.
  - TOTP verification is based on RFC 6238-style HMAC-SHA-1 TOTP and accepts only the drafted secret.
  - MFA confirmation includes a synchronous `draft.reserved` assignment before asynchronous validation, preventing the specifically documented concurrent MFA-confirmation race.

- **FAIL — Recovery codes are not reliably single-use under concurrent requests**
  - In `/api/recovery/verify`, the handler awaits hashing for every stored recovery-code entry before setting `matched.used = true`.
  - Two concurrent requests using the same valid recovery code can both evaluate that entry while `used === false`, both retain it as `matched`, and both later set `matched.used = true` and return `{ ok: true }`.
  - This violates the requirement that verification codes/recovery codes be single-use.

- **FAIL — Concurrent recovery-code regeneration can invalidate a successful response**
  - `/api/recovery/regenerate` awaits `generateRecoveryCodeSet()` before assigning `session.recoveryCodes`.
  - Two simultaneous regeneration requests can both return different plaintext code sets, while only the last set assigned to `session.recoveryCodes` remains valid.
  - A user receiving the earlier successful response may receive recovery codes that cannot be verified.

- **FAIL — Concurrent provisioning can return a setup key that is no longer the active draft**
  - `/api/mfa/provision` generates a secret and awaits `encryptAtRest(seed)` before assigning `session.draft`.
  - Parallel provisioning requests can overwrite one another’s draft after their asynchronous encryption finishes.
  - The UI may show the first response’s setup key and test OTP even though a later request has replaced the server-side draft, causing valid-looking setup data to fail confirmation.

- **FAIL — Sensitive values are exposed in the rendered in-page log panel**
  - The browser UI writes identity codes, authenticator setup secrets, TOTP test codes, and recovery codes into `#logLines`.
  - The requirements explicitly prohibit exposing OTP seeds, OTPs, and backup codes in logs. The required testing `console.log` behavior does not require a persistent, rendered “Logs” pane containing these secrets.
  - The visible log panel also leaves sensitive values displayed after navigation within the SPA.

- **PASS — Mobile UX and semantic structure**
  - The app uses a mobile-responsive, single-column layout, large controls, high-visibility focus styling, labeled inputs, semantic forms, headings, and status/error regions.
  - The setup key can be manually entered, satisfying the manual provisioning requirement without needing a QR code.

## FAILING_ITEMS

- Recovery-code verification has an asynchronous race that can allow the same recovery code to be accepted more than once.
- Recovery-code regeneration is not serialized or transactionally protected; concurrent successful responses can return code sets that are no longer active.
- MFA provisioning is not serialized; concurrent requests can overwrite the active draft and make an earlier displayed setup key/OTP unusable.
- The in-page testing log panel exposes identity codes, TOTP setup secrets, TOTP codes, and backup recovery codes.

## NEW_TASKS

1. Make recovery-code verification atomic: after asynchronous digest computation, re-check that the matched entry is still unused immediately before marking it used, with no intervening `await`; alternatively, use a per-session recovery-operation lock that rejects or serializes concurrent verification attempts.

2. Serialize recovery-code operations per session, covering both `/api/recovery/verify` and `/api/recovery/regenerate`, so a regeneration cannot overwrite recovery state while verification is in progress and simultaneous regenerations cannot return competing active code sets.

3. Add a synchronous per-session provisioning reservation/lock before the first `await` in `/api/mfa/provision`; reject or reuse an in-progress provisioning request so each returned setup key and test OTP corresponds to the active server-side draft.

4. Remove the rendered sensitive `#logs` panel or ensure it never displays identity codes, authenticator seeds, OTPs, session-related values, or recovery codes. Retain the explicitly required browser `console.log` test mocks only.

## DECISION

**FAIL**