## SUMMARY

The artifact is a single-file Bun HTTPS SPA with strong coverage of session authorization, CSRF tokens on authenticated state-changing endpoints, encrypted TOTP-secret storage, hashed recovery codes, rate limiting, secure headers, mobile-focused UI, and accessible MFA steps. However, it does not fully satisfy the requirements because the offered QR provisioning code is not standards-compliant/decodable, and the required deterministic browser-console mock behavior is only enabled through an undocumented environment flag rather than being reliably available as specified. Login/session creation also lacks CSRF protection despite being state-changing.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no framework/build tooling**
  - The entire server, HTML, CSS, and browser JavaScript are contained in `app.ts`.
  - It uses `Bun.serve`, built-in Node filesystem imports, and no external assets or network calls.

- **PASS — HTTPS/TLS server configuration**
  - The server loads `certs/cert.pem` and `certs/key.pem`.
  - It exits rather than silently serving insecure HTTP when certificates are missing.
  - HSTS is returned through the common response-header function.

- **PASS — Server-side authorization and IDOR prevention**
  - MFA routes derive the account exclusively from the `HttpOnly` `mfa_session` cookie.
  - No API route accepts a client-controlled user/account ID.
  - MFA records are retrieved only through `s.userId`, preventing manipulated user identifiers.

- **FAIL — CSRF protection for all state-changing requests**
  - Authenticated state-changing routes correctly require `X-CSRF-Token`.
  - However, `POST /api/signin` creates and rotates a session cookie but does not require a CSRF token.
  - `originOK()` allows requests without an `Origin` header, so the sign-in endpoint is not protected by a strict Origin requirement either.
  - Since login creates a security-sensitive authenticated session, it must receive CSRF/login-CSRF protection.

- **PASS — Secure session-cookie and session-lifecycle handling**
  - Session cookies use `HttpOnly`, `Secure`, `SameSite=Strict`, and a bounded `Max-Age`.
  - A new session ID is created at sign-in and prior sessions for the user are removed.
  - Idle timeout, absolute timeout, and logout invalidation are implemented.
  - Session tokens are not put in browser storage or URLs.

- **PASS — Secure response headers and restricted browser policy**
  - CSP includes a per-page nonce and restricts scripts, styles, connections, forms, and framing.
  - HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Cache-Control: no-store`, and `Permissions-Policy` are present.
  - No permissive CORS headers are returned.

- **PASS — Secret/code generation and at-rest protection**
  - TOTP secrets are encrypted with AES-GCM.
  - Recovery codes are SHA-256 hashed before storage.
  - Random production secrets, recovery codes, session IDs, CSRF tokens, and OTPs use `crypto.getRandomValues`.
  - TOTP codes are checked against the current and previous period and are prevented from reuse.

- **PASS — Validation, injection resistance, and output encoding**
  - JSON payload sizes are bounded.
  - OTPs, recovery codes, and sign-in fields are validated with constrained formats.
  - Client-provided values are not interpolated into server HTML.
  - Dynamic browser insertion of secrets/recovery codes uses escaping before `innerHTML`.

- **PASS — OTP expiry, single use, failed-attempt controls**
  - Identity OTPs expire after 20 minutes and are marked used after verification.
  - TOTP counters are recorded to prevent replay.
  - Recovery codes are one-time use.
  - Five failed attempts produce a five-minute lockout.

- **FAIL — Working QR-code provisioning option**
  - The UI visibly offers a QR code for authenticator provisioning.
  - The custom `qr()` implementation does not produce a standards-compliant QR symbol:
    - QR format-information bits are not generated/written correctly.
    - Reed-Solomon error-correction generation uses incorrect coefficients (`gf[(j+1)*10%255]`) rather than a QR Reed-Solomon generator polynomial.
    - The claimed “standards-compliant” implementation does not perform the stated ISO mask scoring.
  - As a result, authenticator apps cannot be expected to scan the QR code reliably, violating the requirement that an offered QR provisioning option work.
  - The manually displayed/copyable secret is a useful fallback, but it does not make a broken offered QR option acceptable.

- **PASS — Manual authenticator setup and copy-to-clipboard support**
  - The provisioning secret is displayed with issuer, account, algorithm, digits, and period.
  - A copy control is provided for the secret.
  - The user can enter a six-digit authenticator code manually after configuring their authenticator app.

- **PASS — Recovery-code handling**
  - Recovery codes are displayed, can be copied, hidden/revealed, regenerated, and acknowledged.
  - Regeneration invalidates prior recovery-code hashes.
  - Recovery codes are verified as one-time values.

- **FAIL — Required deterministic browser mock behavior is not reliably enabled**
  - The requirements require OTP delivery/provisioning/recovery mocks to be shown through `console.log` in the browser and require deterministic testing values.
  - This behavior only occurs when the server is started with `EVALUATOR_DEMO=true`.
  - In the default configuration, identity OTP delivery is simulated server-side but is neither returned to the browser nor logged in the browser console; generated values are also non-deterministic.
  - The requirement does not specify that the evaluator must set this environment variable, so the delivered artifact does not reliably meet the stated mock/testing behavior.

- **PASS — Mobile and dyslexia-inclusive UI**
  - The layout is responsive and constrained for phone widths.
  - The UI uses readable font sizing, increased spacing, short instructions, examples, icons, clear step labels, prominent primary actions, and no animations/timers.
  - Inputs use suitable autocomplete attributes, including `one-time-code`, and retry/resend controls are provided.
  - Errors are written in plain language and include suggested corrective action.

## FAILING_ITEMS

- `POST /api/signin` creates a new authenticated session but has no CSRF token requirement and accepts requests with no `Origin` header. This does not meet the requirement to apply CSRF protection to all state-changing requests.
- The custom browser QR generator is not a valid QR implementation. It omits valid QR format information, computes Reed-Solomon ECC incorrectly, and does not implement the claimed mask scoring. The displayed provisioning QR code cannot be relied on to scan.
- Deterministic mock OTP/recovery values and browser `console.log` output depend on `EVALUATOR_DEMO=true`, which is not part of the stated runtime instructions. Default behavior does not meet the required browser-based mock delivery/logging behavior.

## NEW_TASKS

1. Add login-CSRF protection for `POST /api/signin`: issue a pre-authentication CSRF token from the initial page or a dedicated same-origin endpoint, require it on sign-in, and require a valid trusted Origin for that request rather than accepting an absent `Origin` header.

2. Replace the custom `qr()` function with a fully standards-compliant, self-contained QR encoder that correctly implements QR byte-mode capacity handling, Reed-Solomon block/error correction, format/version information, masking, and mask selection. Keep it inline in `app.ts` and verify that a standard authenticator app can scan the generated `otpauth://` URI.

3. Make the required deterministic mock flow explicit and reliably available under the required runtime configuration: ensure the simulated identity OTP, authenticator OTP, and recovery codes are returned to the browser and emitted using browser `console.log` for testing without requiring an undocumented environment variable, or document and enforce the required demo-mode startup configuration as part of the delivered artifact.

## DECISION

**FAIL**