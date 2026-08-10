## SUMMARY

The artifact is a single-file Bun HTTPS SPA with strong coverage of session authorization, CSRF, security headers, mobile-friendly UX, recovery-code handling, and browser-side simulated logging. However, it does not provide a functioning authenticator-app setup flow: the displayed “QR code” is decorative rather than decodable, its secret is not valid RFC Base32 TOTP data, and the verification value is a random server challenge rather than a time-based OTP derived from the provisioned secret. The mock OTP is also random rather than deterministic. These defects prevent acceptance.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no framework, build tool, external assets, or external network calls.**  
  The server, HTML, CSS, and browser JavaScript are all in `app.ts`. It uses `Bun.serve`, inline styles/scripts, and no third-party resources.

- **PASS — HTTPS/TLS server setup uses the specified certificate paths.**  
  `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`.

- **PASS — Mobile-responsive and dyslexia-aware UI.**  
  The application uses generous spacing, readable font sizing and letter spacing, plain-language instructions, clear step labels, mobile media styling, no animation, short hints, input examples, and prominent primary actions.

- **PASS — Sign-in and session-management controls.**  
  The application creates a fresh session identifier after sign-in, uses `HttpOnly`, `Secure`, and `SameSite=Strict` cookie attributes, applies idle and absolute timeouts, and invalidates the session on logout.

- **PASS — Server-side ownership enforcement / IDOR protection.**  
  MFA routes are authorized through the server-side session, and the session is checked against the only account ID. Client-supplied account or user IDs are not accepted by the MFA endpoints.

- **PASS — CSRF protection for state-changing authenticated routes.**  
  Authenticated POST operations require a session-bound `X-CSRF-Token` and matching same-origin `Origin` header. Sign-in uses a one-time pre-authentication token and origin check.

- **PASS — Security headers and basic CORS restriction.**  
  Responses include CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, referrer policy, and no-store caching. The application does not permissively allow arbitrary CORS origins.

- **PASS — Input validation and browser output encoding.**  
  JSON request shapes are allow-listed, OTP input is restricted to six digits, sign-in fields are constrained, and dynamic browser-rendered values are escaped with `esc()` before insertion into `innerHTML`.

- **PASS — Rate limiting, expiry, and single-use handling for the current server challenge.**  
  Sign-in and OTP failures are rate limited. The setup challenge has an expiry, lockout behavior, and is marked used after successful verification.

- **FAIL — Authenticator provisioning QR code is not a real QR code.**  
  `renderQR()` draws a pseudorandom matrix based on the URI hash; it does not perform QR encoding with data/error-correction blocks. An authenticator application cannot scan or decode the displayed image, so the advertised QR enrollment option does not work.

- **FAIL — The manually shown provisioning secret is not a valid TOTP/Base32 secret.**  
  The secret is made from Base64URL data, transformed by removing `-`/`_`, then uppercased:
  ```ts
  Buffer.from(...).toString("base64url").replace(/[-_]/g, "").slice(0, 24).toUpperCase()
  ```
  This can include digits such as `0`, `1`, `8`, and `9`, which are invalid in standard Base32 TOTP secrets. Many authenticator apps will reject the URI or produce a different result.

- **FAIL — OTP verification is not time-based and does not verify the provisioned authenticator secret.**  
  `/api/verify-otp` compares the submitted code to a random `challenge.value`. It never calculates a TOTP from `session.provision.seed`. Even if a user could scan the provisioning URI in an authenticator app, the six-digit TOTP it generates will not match the random server challenge.

- **FAIL — Simulated OTP mock value is not deterministic as required.**  
  `otpValue()` uses cryptographic randomness. The requirement calls for deterministic mock values for testability, while still allowing verification to work. The displayed/logged testing value changes randomly for every provisioning request.

- **FAIL — Recovery-code hashes are unsalted fast SHA-256 values.**  
  Recovery codes are stored as direct SHA-256 hashes without a unique salt or a password-hashing/KDF work factor. Although codes are randomly generated, direct fast hashing is not a sufficiently robust storage approach for sensitive recovery credentials under the cryptographic-failure requirement.

## FAILING_ITEMS

- The canvas labelled as an authenticator QR code is not standards-compliant or scannable because `renderQR()` is only a decorative pseudorandom pattern generator.
- Provisioning secrets are not encoded as RFC Base32 secrets suitable for standard `otpauth://totp/` URIs.
- The server does not implement TOTP generation/verification from the encrypted provisioned secret; it verifies an unrelated random challenge instead.
- Mock OTPs are cryptographically random, not deterministic testing values as required.
- Backup recovery codes are stored with unsalted, fast SHA-256 hashes instead of salted, work-factored hashes/KDF-derived records.

## NEW_TASKS

1. Replace `renderQR()` with an in-file, standards-compliant QR encoder that encodes `setupURI` into a scannable QR code; do not add external assets, packages, or network calls.

2. Replace the provisioning-secret generator with cryptographically random RFC Base32 output using only the standard Base32 alphabet `A-Z` and `2-7`, and ensure the same value is used in both the manual-secret display and the `otpauth://totp/` URI.

3. Implement in-file TOTP calculation and verification using the provisioned secret, standard HMAC-based OTP logic, and time steps. Verify submitted codes against the provisioned secret rather than against an unrelated random challenge. Preserve expiry, retry, lockout, and single-use protections as applicable.

4. Add a deterministic browser-console test mock for enrollment verification, such as a documented test-mode code or deterministic test clock/code path. Ensure the test-mode OTP is returned to the UI code and logged only through browser `console.log`, while normal mode verifies real TOTP values.

5. Replace direct recovery-code SHA-256 storage with per-code salted, work-factored KDF records (for example PBKDF2 using Web Crypto), storing the salt and derived hash rather than a direct unsalted digest.

## DECISION

**FAIL**