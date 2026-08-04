## SUMMARY

The artifact is a well-structured single-file Bun application with TLS, secure headers, CSP nonces, CSRF protection, session-bound reset tokens, Argon2id password hashing, throttling, MFA simulation, safe DOM rendering, and a complete recovery/privacy-acceptance UI flow. However, the recovery request endpoint creates and returns a usable reset token solely when a caller supplies the hard-coded test email. This allows any unauthenticated caller who knows or guesses that email to reset the account password, and also makes the request response distinguish the designated account from other addresses. The mock MFA delivery is random rather than deterministic as required.

## FUNCTIONAL_CHECK

- **Recovery flow works end-to-end — PASS**
  - A user can request recovery, open a simulated reset link or manually submit a reset token, verify the token, complete MFA, set a strong password, accept privacy conditions, and reach the completion screen.
  - Internal navigation via hash routes and the reset-link query parameters functions.

- **Single-file Bun application with no build tooling or external assets — PASS**
  - The server, HTML, CSS, and browser JavaScript are contained in `app.ts`.
  - It uses Bun directly and no framework, bundler, compiler, external scripts, fonts, or network resources.

- **TLS certificate usage and HTTPS enforcement — PASS**
  - `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`.
  - Requests whose URL protocol is not HTTPS are rejected.
  - Session cookies use `Secure`, `HttpOnly`, and `SameSite=Strict`.

- **Security headers and browser hardening — PASS**
  - HSTS, CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, cache prevention, permissions policy, COOP, and CORP headers are set.
  - The CSP uses per-response nonces for the server-generated style and script.

- **CSRF protection and session controls — PASS**
  - CSRF tokens are random, session-specific, and required on all POST API routes.
  - The session cookie is HttpOnly, Secure, and SameSite Strict.
  - Reset records are bound to the originating session, preventing a token from being used in an unrelated browser session.

- **Sensitive route authorization / prevention of unauthorized password reset — FAIL**
  - Any caller can submit `helena.test@hospital.example` to `/api/recovery/request` and receive a valid reset token in the HTTP response.
  - The fixed email check is not authorization or proof of control over an enrolled recovery channel.
  - Because the caller receives both the reset token and, after token verification, the MFA code, the caller can reset the designated account password without prior authentication or ownership verification.

- **Account enumeration resistance and privacy-preserving recovery response — FAIL**
  - The nominal `message` is generic, but the response is observably different for the designated account: it includes `testToken`, `resetLink`, and `mfaDeliveryPending`.
  - Requests for all other addresses do not receive these fields. This exposes whether the designated account exists and is enrolled in recovery.

- **Reset-token security — PASS**
  - Tokens are generated from cryptographically secure random bytes, stored only as SHA-256 hashes, session-bound, short-lived, and deleted after use.
  - Token replay is prevented with the `used` flag and removal from the token map.
  - Reset links are same-origin relative URLs, and `Referrer-Policy: no-referrer` reduces URL-token leakage.

- **Password policy and storage — PASS**
  - New passwords require at least 12 characters with upper-case, lower-case, numeric, and symbol characters.
  - Passwords are hashed with Bun Argon2id and are not stored in plaintext.
  - The initial account password is also generated and immediately hashed rather than retained in plaintext.

- **Brute-force protections — PASS**
  - Recovery requests, token verification attempts, and MFA attempts are rate limited.
  - Limits include a coarse server-derived client IP grouping and a normalized identifier where available.

- **MFA / additional verification — PASS**
  - Password reset requires reset-token verification and a second MFA-code verification before a password can be changed.
  - MFA codes are stored as hashes in reset records and deleted after successful MFA completion.

- **Deterministic mock delivery values — FAIL**
  - The requirements call for simulated delivery and verification using console logging and deterministic mock values.
  - `newMfaCode()` generates a random MFA code using `randomBytes`, so the mock MFA value is not deterministic.
  - The browser logging behavior itself is correctly implemented: the reset token and MFA code are logged in the browser console and displayed in the Logs panel.

- **XSS and injection resistance — PASS**
  - Browser-rendered dynamic content is inserted through `textContent`, DOM node creation, `.value`, and `replaceChildren`, not `innerHTML`.
  - User-controlled values are not interpolated into the HTML template.
  - JSON request bodies are validated as objects before field handling.

- **No external calls, open redirects, or SSRF paths — PASS**
  - All browser fetches use same-origin relative paths.
  - The generated reset link is a relative internal path.
  - No user-controlled destination URL is accepted or fetched by the server.

- **Anti-phishing / social-engineering guidance — PASS**
  - The interface prominently tells users not to disclose passwords, reset tokens, or verification codes to email, phone, or support contacts.
  - The application identifies the verified local portal as the only place to enter codes.

- **Error handling and production exposure — PASS**
  - Request parsing and password hashing errors return generic user-facing messages.
  - The application does not return stack traces, directory listings, account IDs, password hashes, or other stored patient data.

## FAILING_ITEMS

- **Unauthenticated password-reset takeover:** Supplying the hard-coded designated email address is sufficient to receive a working reset token. The endpoint does not require proof that the requester controls an enrolled recovery channel.
- **Account enumeration through response shape:** The recovery-request response differs for the designated account because it exposes `testToken`, `resetLink`, and `mfaDeliveryPending`, while unknown accounts receive only the generic response.
- **Non-deterministic MFA mock:** The simulated MFA code is random, despite the requirement for deterministic mock values for simulated delivery/verification.

## NEW_TASKS

1. **Remove the email-only recovery authorization bypass.**
   - Require an authenticated or otherwise verified simulated enrolled-recovery-channel proof before issuing a usable password-reset token.
   - Do not treat knowledge of `helena.test@hospital.example` as authorization to reset that account.

2. **Make recovery-request responses indistinguishable regardless of account existence or enrollment.**
   - Ensure that unknown, unenrolled, and enrolled-account requests return the same status, message, and JSON field structure.
   - Move any test-only delivery mechanism behind an explicit protected test-mode mechanism that cannot be triggered merely by submitting a known email.

3. **Use deterministic simulated MFA delivery values.**
   - Replace the random MFA mock code with a deterministic test value or deterministic derivation suitable for the simulated flow.
   - Continue storing only a hash of the code in the reset record and retain existing attempt throttling.

## DECISION

**FAIL**