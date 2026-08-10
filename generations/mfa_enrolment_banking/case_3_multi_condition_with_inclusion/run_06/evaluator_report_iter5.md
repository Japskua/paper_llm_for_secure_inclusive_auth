## SUMMARY

The artifact is a single-file Bun/TypeScript MFA application with strong security-oriented server logic, responsive mobile UI, TLS configuration, encrypted OTP-secret storage, hashed recovery codes, CSRF checks, session cookies, rate limiting, and test-mode browser console output. However, the primary enrolment flow is currently broken immediately after successful identity verification: the server rotates the session and CSRF token, but the browser keeps using the old CSRF token. This prevents provisioning, OTP verification, backup-code generation, completion, logout, and recovery verification. The default non-test application is also not usable because it has no sign-in mechanism capable of creating an authenticated session.

## FUNCTIONAL_CHECK

- **FAIL — Full MFA enrolment flow works end-to-end.**  
  Identity verification rotates the session in `/api/identity/verify`:
  ```ts
  const replacement = createAuthenticatedSession(true);
  ```
  The replacement session has a new `csrf` token, but the response only returns `{ ok: true }`. The client retains the old value in `csrf`, so its next call to `/api/provision` fails `csrfOkay()` with HTTP 403. The user cannot continue beyond step 1.

- **FAIL — Marcus can sign in and begin MFA setup in the normal application mode.**  
  When `MFA_TEST_MODE` is not `1`, the UI states that no public sign-in service exists and does not provide any way to establish an authenticated account-owner session. Since `GET /api/bootstrap` requires a session and no normal authentication route exists, the normal application cannot enter the enrolment flow.

- **PASS — The app is a single-file Bun application with inline HTML, CSS, and vanilla browser JavaScript.**  
  The server, HTML template, CSS, and client logic are all contained in `app.ts`. No framework, bundler, compiler step, or external asset is used.

- **PASS — TLS and secure response headers are configured.**  
  Bun is configured with:
  ```ts
  tls: { cert: "certs/cert.pem", key: "certs/key.pem" }
  ```
  and responses include CSP with per-page nonces, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, and `Cache-Control: no-store`.

- **PASS — Session cookies and session expiry protections are present.**  
  The session cookie is `HttpOnly`, `Secure`, and `SameSite=Strict`. Server-side sessions have idle and absolute expiry checks, are deleted on logout, and are rotated after successful identity verification.

- **PASS — MFA endpoints enforce authenticated account ownership and reject user-ID manipulation.**  
  Protected API routes call `requireOwner()`, and the account ID is server-controlled rather than accepted from the browser. No API accepts a client-provided user/account identifier, preventing straightforward IDOR manipulation.

- **PASS — State-changing authenticated MFA operations use CSRF validation.**  
  Authenticated POST endpoints require both a trusted `Origin` and a matching `X-CSRF-Token`. Session cookies also use `SameSite=Strict`.

- **PASS — OTP secret and backup-code storage use appropriate cryptographic protections.**  
  OTP secrets are encrypted at rest with AES-256-GCM using a random 32-byte key. Backup codes are generated with `randomBytes()` and stored as salted `scrypt` hashes. Recovery codes are removed after successful use.

- **PASS — Verification code controls are implemented.**  
  Identity codes expire after 15 minutes and are marked used after verification. TOTP replay prevention is implemented through `lastAcceptedTotpCounter`. Failed verification attempts are rate-limited with a five-failure lockout for five minutes.

- **PASS — Server-side validation and output escaping are generally implemented.**  
  Phone suffixes, six-digit OTPs, and recovery-code formats are validated. Dynamic values inserted into browser HTML use `esc()`, and no database/query injection surface exists because the artifact does not use SQL or an external database.

- **FAIL — Inclusive UX confirms successful actions clearly at every step.**  
  A successful “Send or re-send code” action does not provide a visible confirmation in normal mode. The browser only inserts an academic-test value card when `testMode` is enabled; otherwise, it silently focuses the code field. The requirements call for plain confirmation of what happened and what to do next.

- **FAIL — The UI supports reveal/hide and re-request behaviour for displayed sensitive values.**  
  The UI supports re-sending the identity code and regenerating backup codes, but it does not provide reveal/hide controls for the displayed setup key or backup codes. These values remain visibly displayed once generated. This does not fully meet the requirement to let users reveal, hide, and re-request codes without penalty.

- **PASS — Mobile readability and dyslexia-conscious presentation are substantially addressed.**  
  The page uses a constrained mobile-width layout, large controls, generous line-height and letter spacing, short plain-language instructions, examples of expected input, icons paired with text, prominent primary actions, static content, and accessible focus states.

- **PASS — Test-mode mocks are surfaced in the browser and logged in the browser console.**  
  In test mode, the identity code, authenticator code, and backup recovery codes are returned to the UI and logged with browser-side `console.log`. No secrets are logged by the server.

## FAILING_ITEMS

- The application cannot proceed after identity verification because session rotation invalidates the client’s CSRF token without giving the client the replacement token.
- The default non-test application has no functional authentication path, so no account owner can begin MFA enrolment unless the server is launched with `MFA_TEST_MODE=1`.
- A successful normal-mode identity-code send has no visible confirmation message explaining that the code was sent and that the user should enter it.
- Setup secrets and backup codes lack hide/reveal controls, despite the stated requirement to allow users to reveal and hide codes.

## NEW_TASKS

1. Update `/api/identity/verify` to return the replacement session’s CSRF token, and update the browser client to replace its in-memory `csrf` value before making subsequent MFA API requests.
2. Add a secure, clearly scoped mock authenticated-session entry path for normal/demo operation, or document and enforce a required upstream authentication integration so the normal application can actually create an authenticated account-owner session.
3. After successful `/api/identity/send`, render a plain visible success message such as: “Code sent to the phone ending in 4821. Enter the six digits when you are ready.”
4. Add accessible hide/reveal controls for the authenticator setup key and generated backup codes, while retaining copy and regenerate/re-request options.

## DECISION

FAIL