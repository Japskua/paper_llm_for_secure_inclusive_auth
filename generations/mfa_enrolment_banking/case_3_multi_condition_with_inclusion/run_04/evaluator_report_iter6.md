## SUMMARY

The artifact is a well-structured single-file Bun SPA with responsive, accessible MFA enrolment screens, TLS configuration, secure headers, CSRF tokens, encrypted TOTP storage, hashed recovery codes, and working simulated OTP/recovery-code flows. However, it fails a core security requirement: any unauthenticated visitor can invoke the public mock-proof endpoints and receive an authenticated session for Marcus’s account. This means account ownership is not actually enforced server-side. The proof rate-limit key is also bypassable through a client-supplied `X-Forwarded-For` header.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no framework, bundler, compiler, or external assets**
  - All server, HTML, CSS, and browser JavaScript are contained in `app.ts`.
  - The page is served by Bun directly and uses only browser APIs and inline code.
  - TLS certificates are read from the required `certs/cert.pem` and `certs/key.pem` paths.

- **PASS — Mobile-responsive, dyslexia-aware UI**
  - The interface has a mobile viewport tag, constrained layout, responsive CSS, generous spacing, large inputs/buttons, plain language, examples, icons, and no moving/auto-updating content.
  - OTP and recovery-code screens include clear examples and retry-oriented messages.
  - Manual secrets and recovery codes can be revealed, hidden, copied, and regenerated.

- **PASS — Authenticator provisioning and verification flow works**
  - Provisioning creates a CSPRNG-generated Base32 secret, creates an `otpauth://` URI, renders a QR code, supports reveal/copy of the manual secret, and validates six-digit TOTP values.
  - The browser logs the mock TOTP value and recovery codes as explicitly required for testing.
  - OTPs are time-bound and TOTP time steps are single-use through `usedSteps`.

- **PASS — Recovery-code flow works**
  - Eight recovery codes are generated with cryptographically secure randomness.
  - Only salted/peppered SHA-256 hashes are retained in the MFA record.
  - A recovery code is deleted after successful use, making it single-use.
  - Regeneration invalidates prior recovery-code hashes.

- **PASS — CSRF protection for state-changing requests**
  - State-changing API calls require `X-CSRF-Token`.
  - The CSRF token is tied to the server-side session.
  - Origin checks and `SameSite=Strict` session cookies provide additional protection.

- **PASS — Secure session-cookie attributes and session lifecycle**
  - Cookies are set with `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - The session has idle and absolute expiry checks.
  - Session IDs are rotated after the proof completion flow.
  - Logout invalidates the server-side session and clears the cookie.

- **PASS — Security headers and TLS configuration**
  - The app sets CSP with per-page nonces, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, and `Cache-Control: no-store`.
  - Bun is configured as a TLS server using the required certificate paths.
  - API errors are generic and stack traces are not returned.

- **PASS — Input validation and output encoding**
  - OTPs and recovery codes are validated server-side with strict formats.
  - Client-rendered dynamic text is escaped before use in `innerHTML`.
  - There are no user-controlled redirect destinations or SQL queries.

- **FAIL — Server-side authorization ensures only the authenticated account owner can access Marcus’s MFA settings**
  - `/api/proof/start` is reachable by any unauthenticated session and calls `issueFixtureProof(session!)`.
  - `issueFixtureProof()` always issues a valid proof for the hard-coded Marcus account when `authenticatedFixture.enabled` is true.
  - Any visitor can then call `/api/proof/complete` and receive a logged-in session with `userId: "acct_marcus_001"`.
  - The browser does not submit an `approved` flag, but the server still grants Marcus authentication to arbitrary unauthenticated visitors. This is an authentication and access-control failure, not a valid account-owner authorization check.

- **FAIL — Failed identity-verification attempts are reliably rate-limited**
  - `clientProofKey()` trusts the request header `X-Forwarded-For`.
  - A direct client can supply a different `X-Forwarded-For` value on each request, creating a new rate-limit key and bypassing proof-attempt lockouts.
  - `X-Forwarded-For` may only be used when it is injected and verified by a trusted reverse proxy, not when it comes directly from an arbitrary client.

## FAILING_ITEMS

- Any unauthenticated browser visitor can complete the mock identity flow and obtain an authenticated server session for Marcus’s account.
  - The flaw is in the server-side authentication design, specifically the public `/api/proof/start` endpoint issuing a valid Marcus proof without validating any user-specific credential, signed assertion, or pre-existing authenticated identity.

- The identity-proof rate limit can be bypassed by spoofing `X-Forwarded-For`.
  - The rate-limit identity must not be derived from an untrusted client-controlled forwarding header.

## NEW_TASKS

1. Replace the public hard-coded Marcus proof grant with a server-side authentication/identity-proof mechanism that validates a user-specific credential or trusted server-side identity assertion before assigning `session.userId = account.id`.
   - Do not issue an authenticated Marcus session merely because a client clicked “Start identity check.”
   - Keep the simulated flow, but make its successful proof dependent on a server-validated mock credential or a trusted pre-authenticated fixture rather than an endpoint available to every anonymous visitor.
   - Return generic failure messages and retain session-ID rotation after successful authentication.

2. Replace `clientProofKey()`’s use of arbitrary `X-Forwarded-For` input with a non-spoofable rate-limit key.
   - Rate-limit proof failures by server session/account plus a server-trusted network identity.
   - Only read forwarded client-IP headers when requests are known to arrive through a configured trusted proxy; otherwise ignore them.
   - Ensure changing a client-supplied header cannot reset or bypass the failed-proof lockout.

## DECISION

**FAIL**