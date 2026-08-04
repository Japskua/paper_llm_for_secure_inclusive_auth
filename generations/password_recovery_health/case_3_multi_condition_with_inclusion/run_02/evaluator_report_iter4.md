## SUMMARY

The artifact is a well-structured single-file Bun HTTPS SPA with accessible, low-stress recovery UX, CSP nonces, CSRF validation, session cookies, password hashing, MFA simulation, and working client-side navigation. However, it fails a critical authentication requirement: any user who knows a registered identifier can request a recovery token, receive that token directly in the response/browser console, reset that account’s password, and complete MFA using another code returned directly to the browser. This permits unauthorized account takeover in the provided mock system.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no build tools/frameworks**
  - The complete server, HTML, CSS, and vanilla browser JavaScript are contained in `app.ts`.
  - It uses `Bun.serve` directly and does not require bundling, compilation, external assets, or external network requests.

- **PASS — HTTPS/TLS server configuration**
  - The Bun server is configured with `certs/cert.pem` and `certs/key.pem`.
  - Secure cookies use `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, and a valid `__Host-` cookie name configuration.

- **PASS — Structured, ADHD-conscious recovery UX**
  - The UI provides numbered visible progress, one panel at a time, clear next-step wording, explicit Continue buttons, persistent session-oriented progress, help text, and no countdown pressure.
  - Feedback is presented through `aria-live` regions and the flow avoids unexpected automatic transitions.

- **PASS — Manual recovery-code submission and simulated recovery link**
  - The recovery code can be entered manually in the verification field.
  - A simulated recovery link is generated and handled through `/?reset=...`, which correctly opens the verification step.

- **PASS — Browser-side simulated delivery logging**
  - Recovery tokens, MFA codes, password-reset completion, privacy acceptance, and appointment confirmation are logged through browser `console.log`.
  - Recovery and MFA test values are also visibly available in the in-page demonstration logs.

- **PASS — CSRF protections for state-changing API requests**
  - Sensitive POST routes require a session, same-origin `Origin` header, and session-specific `X-CSRF-Token`.
  - The CSRF value is random and generated per session.

- **PASS — Password policy, hashing, MFA, and login throttling**
  - New passwords require at least 12 characters and upper-case, lower-case, numeric, and symbol characters.
  - Passwords are stored using `Bun.password.hash(..., { algorithm: "argon2id" })`.
  - Login and code verification apply a five-failure lockout.
  - MFA is required before privacy acceptance and appointment confirmation.

- **PASS — Reset token implementation details**
  - Reset tokens are cryptographically random, session-bound, short-lived, compared with a timing-safe comparison, invalidated after successful use, and cannot be reused.
  - Expired reset authorization is downgraded and cannot authorize a password change.

- **PASS — XSS/output handling and security headers**
  - User-provided identifiers are not reflected into HTML.
  - Dynamic client-visible text is assigned with `textContent`.
  - CSP uses per-page nonces; HSTS, `X-Frame-Options`, `X-Content-Type-Options`, referrer policy, permissions policy, cache prevention, and COOP headers are configured.

- **FAIL — Password recovery prevents unauthorized access**
  - A known account identifier is sufficient to obtain a usable password-reset token.
  - `POST /api/recovery/request` returns `testToken` for both known and unknown accounts. For known accounts, `reset.decoy` is `false`, so the exposed token authorizes a real password replacement.
  - An attacker can submit `helena@example.com`, receive the token, call `/api/recovery/verify`, set a new password, sign in, receive the MFA code in the browser response, and access protected actions.
  - This violates the requirements that the reset flow prevent unauthorized access and that reset links/tokens not be interceptable or usable by unauthorized parties.

- **FAIL — Sensitive recovery authorization is exposed directly to the requester**
  - The response from `genericRecoveryResponse()` includes `testToken`, and browser JavaScript logs it:
    - `testToken: token`
    - `console.log("[mock delivery] Recovery token for testing: " + token)`
  - For a real registered account this is not merely a display-only testing value; it is the actual server-authorizing reset token.

- **FAIL — Robust handling of malformed cookies**
  - `cookieValue()` calls `decodeURIComponent()` on attacker-controlled cookie content without a local `try/catch`.
  - A malformed percent-encoded cookie can throw, reach the outer request handler catch block, and produce a server error response instead of safely ignoring the malformed cookie and starting a new session.

## FAILING_ITEMS

- **Critical account-takeover vulnerability:** Any party who knows a valid account identifier can receive a real reset token from `/api/recovery/request`, reset the account password, and then receive the MFA code after signing in.
- **The test token is a live authorization secret:** `testToken` is returned to the browser for real accounts rather than being a non-authorizing mock value or being restricted to an authenticated/development-only test mechanism.
- **MFA does not mitigate the reset-token exposure in this mock:** The actual MFA code is returned in the `/api/login` response, so an attacker who reset the password can complete MFA.
- **Malformed cookie input can trigger a 500 response:** `decodeURIComponent` in cookie parsing is not safely handled.

## NEW_TASKS

1. Change the recovery mock design so that browser-visible recovery test values cannot authorize a real account password reset solely from knowledge of an identifier.
2. Require a separate simulated possession/identity-verification factor before binding a reset authorization to an existing account, and ensure the factor cannot be obtained merely by submitting the identifier.
3. Keep any browser-displayed `testToken` as a decoy-only token, or restrict test-token exposure to a clearly isolated development/test mode that cannot affect real/pre-provisioned accounts.
4. Ensure that password replacement for a real account requires successful completion of the separate recovery verification factor, not only possession of a token issued by the recovery-request endpoint.
5. Ensure the MFA demonstration code cannot turn a compromised password reset into full authentication; use a separate simulated channel/verification condition or strictly isolate demo authentication from real account authorization.
6. Wrap cookie decoding in safe error handling so malformed cookies are treated as absent/invalid rather than causing a server error.

## DECISION

**FAIL**