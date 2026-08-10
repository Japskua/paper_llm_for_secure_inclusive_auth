## SUMMARY

The artifact is a single-file Bun/TypeScript MFA enrolment app with a polished mobile UI, simulated TOTP and recovery-code verification, TLS setup, session cookies, CSRF checks, encrypted OTP secrets, hashed recovery codes, and several appropriate security headers. However, it does not fully meet the requirements because the QR-code provisioning option is missing, the displayed hard-coded credential allows any visitor to authenticate as Marcus, proof-attempt rate limiting can be bypassed by obtaining a new session, and recovery-code regeneration failures can misleadingly claim that codes were saved.

## FUNCTIONAL_CHECK

- **Single `app.ts` file containing Bun server, HTML, CSS, and browser JavaScript: PASS**
  - The supplied artifact is one TypeScript file and embeds the server, HTML template, inline CSS, and vanilla browser JavaScript.
  - It does not use frameworks, bundlers, compilation steps, or external assets.

- **Bun TLS server uses the supplied certificate paths: PASS**
  - The server loads `certs/cert.pem` and `certs/key.pem` using `readFileSync`.
  - `Bun.serve` is configured with `tls: { cert, key }`.

- **Mobile-responsive, dyslexia-aware UI: PASS**
  - The layout has a mobile-sized content shell, responsive small-screen CSS, generous padding, readable font sizing, focus styling, short instructional text, icons, clear examples, and no animations or timers.
  - OTP entry uses `inputmode="numeric"` and `autocomplete="one-time-code"`.

- **Clear progressive MFA enrolment flow: PASS**
  - The UI provides identity confirmation, authenticator setup, OTP verification, recovery-code generation, recovery-code verification, completion, and logout.
  - Progress indicators and a prominent primary action are provided at each stage.

- **Copy-to-clipboard support: PASS**
  - Manual authenticator secrets and recovery codes have copy actions using `navigator.clipboard.writeText`.
  - Copy failures are handled with user-facing instructions.

- **QR-code provisioning option: FAIL**
  - The requirements explicitly require QR-code options in addition to copy-to-clipboard support.
  - `/api/provision` returns only `manualSecret` and `testOtp`; it does not return an `otpauth://` provisioning URI or QR payload.
  - The client has no QR-code rendering, scanning, download, or provisioning-URI display option.

- **Manual secret entry option when provisioning details are offered: PASS**
  - The server returns a Base32 secret and the UI allows the user to reveal and copy it.
  - The user can manually enter the secret into an authenticator app.

- **Simulated OTP and recovery codes are available to the browser console: PASS**
  - The browser-side `log()` function calls `console.log`.
  - The test authenticator code and recovery codes are logged from browser code, not server-side logging.
  - The OTP verification logic is functional and accepts the current or immediately preceding TOTP time step.

- **OTP and recovery-code verification behavior: PASS**
  - TOTP verification is time-bound, single-use per accepted TOTP step, and validates six digits.
  - Recovery codes are cryptographically generated, are stored as hashes, and are consumed using `Set.delete()`, making them one-time-use.

- **Authenticated ownership and IDOR prevention: FAIL**
  - Protected MFA routes correctly use the server-side session and never accept a user ID from the client.
  - However, the only credential required to become authenticated as Marcus is `MARCUS-DEMO-2025`, and that exact credential is visibly displayed in the public UI as the input example.
  - Any visitor can submit the displayed credential, receive an authenticated Marcus session, and then view or modify Marcus’s MFA configuration. This does not enforce that only the actual account owner can access the account.

- **CSRF protection on state-changing endpoints: PASS**
  - State-changing endpoints require `X-CSRF-Token`, a valid session, and trusted Origin validation.
  - The session cookie has `SameSite=Strict`, which provides additional CSRF protection.

- **Secure session handling: PASS**
  - Session identifiers are cryptographically random.
  - Cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - Sessions have idle and absolute expiry handling.
  - The session ID is rotated after identity completion.
  - Logout deletes the session and clears the cookie.

- **Rate limiting and lockout of repeated failed verification: FAIL**
  - TOTP and recovery-code attempts are rate-limited and locked at the MFA-record level.
  - Identity-proof failures are keyed partly by the server session ID in `proofKey()`. An attacker can create a new anonymous session via `GET /api/session` and reset the effective proof-attempt key, bypassing the proof lockout.
  - This does not reliably satisfy the requirement to rate-limit and lock repeated failed verification attempts.

- **Secure headers and clickjacking controls: PASS**
  - Responses include CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, `Permissions-Policy`, and no-store caching.
  - The HTML page uses a per-page CSP nonce for its inline style and script.

- **CORS restriction: PASS**
  - The application does not permit arbitrary CORS origins.
  - Preflight handling allows only the configured localhost HTTPS origins.

- **Secret storage and cryptographic generation: PASS**
  - TOTP secrets are generated with `crypto.getRandomValues` and stored encrypted with AES-GCM.
  - Recovery codes use cryptographically secure random values and are stored only as hashes with a server-side pepper.
  - Browser storage APIs and non-HttpOnly cookies are not used for secrets or sessions.

- **Server-side input validation and output escaping: PASS**
  - Credential, OTP, and recovery-code formats are validated server-side.
  - The UI escapes dynamic text before inserting it into `innerHTML`.
  - No database queries or redirect parameters are present, so SQL injection and open redirects are not introduced.

- **Recovery-code re-request/retry UX: FAIL**
  - `/api/generate-recovery` requires a recent authenticator verification. After five minutes it returns `needsConfirmation: true`.
  - `makeCodes()` handles this error by calling `complete(error(r.message))`.
  - `complete()` always renders the statement “Authenticator enabled and recovery codes saved,” even when recovery-code generation failed and no new codes were produced.
  - There is no UI path from that error state to re-confirm the authenticator and retry recovery-code generation, despite the requirement to let users re-request codes and retry without penalty.

- **No server-side logging of OTP secrets, OTPs, recovery codes, or tokens: PASS**
  - The server does not log sensitive MFA values.
  - Browser `console.log` output is intentional and specifically required for the mock/demo behavior.

- **Code validity / runtime structure: PASS**
  - The TypeScript and embedded browser JavaScript are syntactically coherent.
  - The server routes, CSP nonces, fetch calls, TLS setup, and DOM handlers are internally consistent.
  - Runtime startup still depends on the required certificate files being present at the specified paths, as required.

## FAILING_ITEMS

- The app does not provide any QR-code or provisioning-URI option for authenticator setup.
- The public UI reveals the exact credential needed to authenticate as Marcus: `MARCUS-DEMO-2025`.
- Because that shared credential is publicly disclosed, any visitor can obtain a session for `acct_marcus_001` and modify that account’s MFA settings.
- Identity-proof rate limiting is bypassable because `proofKey()` includes the session ID; a fresh anonymous session produces a new rate-limit bucket.
- When recovery-code regeneration requires renewed authenticator confirmation, the UI incorrectly shows the successful completion state and says recovery codes were saved.
- The recovery-code regeneration failure path does not offer a direct re-authentication-and-retry flow.

## NEW_TASKS

1. Add an authenticator provisioning URI and an inline QR-code option to `/api/provision` and the setup UI, while retaining the existing reveal/copy manual Base32 secret option.
2. Replace the publicly displayed, globally valid Marcus credential with a server-established authenticated-owner test fixture that cannot be obtained merely by reading the public page; ensure only that authenticated owner session can reach Marcus’s MFA routes.
3. Change proof-attempt rate-limit keys so a new session cannot reset failed-attempt counts; use a stable server-observed network/account context and retain lock state independently of anonymous session IDs.
4. Update `makeCodes()` to handle `needsConfirmation` by showing an authenticator re-confirmation screen, then retrying recovery-code generation after successful OTP verification.
5. Ensure recovery-code generation errors do not render the completion message “Authenticator enabled and recovery codes saved” unless codes were actually generated and presented to the user.

## DECISION

FAIL