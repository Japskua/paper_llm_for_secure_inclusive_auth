## SUMMARY

The artifact is a strong single-file Bun/TypeScript MFA enrolment demo with a responsive mobile UI, TLS, secure cookies, CSP/HSTS, server-side session authorization, CSRF checks, encrypted TOTP seeds, hashed recovery codes, expiry/single-use protections, and deterministic browser-visible test mocks. However, it does not fully meet the anti-enumeration requirement because the sign-in validation path performs observably different work for allow-listed versus unknown identities, creating a potential response-timing account-enumeration side channel.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no framework/build tooling**
  - The server, HTML, CSS, and browser-side vanilla JavaScript are all contained in `app.ts`.
  - It runs directly through Bun and uses no bundler, compiler, framework, CDN, or external UI asset.
  - Certificate files are read from the required `certs/cert.pem` and `certs/key.pem` locations.

- **PASS — Mobile-responsive MFA enrolment UX**
  - The HTML includes a mobile viewport declaration.
  - The layout constrains content to a mobile-friendly width, uses readable typography, touch-sized controls, and includes a narrow-screen media query.
  - The flow covers identity verification, authenticator provisioning, authenticator confirmation, backup-code display, confirmation, MFA settings, code regeneration, recovery-code verification, and logout.

- **PASS — Browser-side simulation logging and manual authenticator setup**
  - Identity test codes, authenticator test codes, provisioning secrets, and backup codes are emitted through browser `console.log`.
  - The same controlled simulation output is visible in the UI’s Logs panel.
  - The authenticator secret is available for manual entry into an authenticator app, satisfying the manual-submission requirement where no QR code is provided.
  - Test OTP verification works deterministically in the default test mode.

- **PASS — Server-side authorization and IDOR prevention**
  - MFA endpoints obtain the authenticated session server-side and derive the account only from `session.accountId`.
  - No MFA endpoint accepts a user/account identifier from the client.
  - The submitted identity is checked against a server-side allow-list before a session is created.
  - Session ownership is checked for `/api/state`, provisioning, OTP verification, backup-code regeneration, recovery-code use, and logout.

- **PASS — CSRF protections**
  - State-changing authenticated requests require both a session-specific `X-CSRF-Token` and a trusted `Origin`.
  - Pre-authentication state-changing requests also require a trusted origin.
  - Cookies use `SameSite=Strict`, providing an additional CSRF mitigation.

- **PASS — Secure transport, cookies, headers, and CORS**
  - Bun is configured with TLS certificates and rejects non-HTTPS request URLs.
  - HSTS, CSP, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, and no-store caching headers are applied.
  - Session and challenge cookies are `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, and correctly use the `__Host-` prefix constraints.
  - CORS is restricted to explicit localhost HTTPS origins and credentials are only enabled for those trusted origins.
  - Error responses are generic and do not expose stack traces.

- **PASS — Cryptographic secret handling**
  - TOTP seeds are generated with cryptographically secure random values and stored encrypted with AES-GCM.
  - Recovery codes are generated from cryptographically secure randomness and stored as separately salted PBKDF2-SHA-256 hashes.
  - OTP provisioning has a limited lifetime.
  - Recovery codes are single-use and replacement generation permanently invalidates prior codes.
  - Browser storage APIs and non-HttpOnly cookies are not used for secrets or session state.

- **PASS — Input validation, output safety, and redirect restrictions**
  - Server-side validation exists for email addresses, phone numbers, OTP values, and recovery-code format.
  - Redirect values are limited to an internal route allow-list.
  - Dynamic browser content that may include secret values is inserted with `textContent`, rather than interpolated as HTML.
  - There is no SQL/database layer, so parameterized-query requirements are not applicable to this in-memory demo.

- **PASS — OTP expiry, replay prevention, lockouts, and session lifecycle**
  - Identity challenges expire, are bound to the authenticated identity, and are deleted after use.
  - Authenticator provisioning expires and cannot be reused after successful activation.
  - TOTP validation allows only the adjacent time steps and rejects replay for an accepted counter.
  - Failed identity, OTP, and recovery-code attempts are rate-limited with a lockout threshold and lock duration.
  - Session identifiers are rotated on sign-in, have idle and absolute expiration, and are invalidated on logout.

- **FAIL — Avoid account/user enumeration in response timing**
  - Responses are generic and the identity-challenge endpoint intentionally creates decoy challenges for unknown identities.
  - However, `/api/signin` has different execution paths for known and unknown identities. In particular, `valid` begins with `!!account && ...`; JavaScript short-circuit evaluation causes unknown identities to skip the subsequent challenge-account binding, expiry, and code checks that known identities execute.
  - This creates distinguishable server processing time between unknown identities and known identities with invalid codes, violating the requirement to avoid enumeration through response timing.

## FAILING_ITEMS

- **Potential account enumeration through `/api/signin` timing**
  - Unknown identities short-circuit at `!!account`.
  - Allow-listed identities continue through challenge ownership, identity-key, used-state, expiry, and code checks.
  - Although HTTP status and body are generic, the differing work may reveal whether an identity is allow-listed through repeated timing measurements.

## NEW_TASKS

1. **Make sign-in authentication evaluation timing-uniform for known and unknown identities.**
   - Refactor `/api/signin` so it always performs equivalent challenge lookup, expiry/used-state evaluation, identity-key comparison, and fixed-time code comparison before determining validity.
   - Use a non-authenticating dummy account/challenge comparison path when no allow-listed account exists, rather than short-circuiting on `!!account`.
   - Preserve the existing generic response body/status behavior and do not create a valid session for unknown identities.

## DECISION

**FAIL**