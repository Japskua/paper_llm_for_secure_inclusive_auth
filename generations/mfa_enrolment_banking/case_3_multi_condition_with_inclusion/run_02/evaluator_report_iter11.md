## SUMMARY

The artifact is a single-file Bun HTTPS SPA with a strong overall MFA flow, mobile-friendly UI, server-side sessions, CSRF checks, TLS configuration, security headers, encrypted TOTP secret storage, hashed recovery codes, rate limiting, and deterministic browser-console test values. However, it has a material functional defect: the hand-built QR encoder generates incorrect Reed–Solomon error-correction data, so the displayed QR code is not standards-compliant and may fail to scan in authenticator apps. It also unnecessarily retains the provisioning URI, including the plaintext TOTP seed, in server memory.

## FUNCTIONAL_CHECK

- **Single `app.ts` Bun server with inline HTML, CSS, and vanilla browser JavaScript — PASS**
  - The entire application is contained in one file.
  - It uses `Bun.serve`, inline HTML/CSS/JS, no framework, no bundler, no compiler, and no external network assets.

- **HTTPS/TLS using the supplied mkcert paths — PASS**
  - Bun is configured with `certs/cert.pem` and `certs/key.pem`.
  - The application advertises and serves HTTPS on port 3000.

- **Responsive and dyslexia-conscious mobile UI — PASS**
  - The UI uses a narrow mobile layout, readable font sizing, generous line height and letter spacing, visible focus styles, short instructions, examples, hints, and consistent step headings.
  - It avoids animation, flashing, dense paragraphs, and forced reading deadlines.
  - It provides reveal/hide and copy actions for long values.

- **Sign-in and identity verification flow works — PASS**
  - The sign-in endpoint validates inputs and creates a new secure session.
  - Identity codes are generated server-side, time-bound, single-use after success, rate-limited, and replacement codes invalidate prior codes.
  - Test identity codes are logged in the browser console as required for mocks.

- **TOTP provisioning and manual setup support — PARTIAL / FAIL**
  - Manual setup is supported: the secret can be revealed and copied, and the setup URI can be copied.
  - TOTP generation and verification use HMAC-SHA1 with Base32 secrets and a time window.
  - However, the QR code implementation is defective and therefore the offered QR setup path cannot be accepted as reliably functional.

- **QR code provisioning option — FAIL**
  - The Reed–Solomon generator polynomial construction in `qr()` is incorrect because it mutates polynomial coefficients in place while computing the next coefficient.
  - This produces invalid error-correction codewords. A standard QR decoder is likely to detect too many erroneous ECC symbols and reject the code rather than scan the provisioning URI.
  - The internal `validatePayload()` check only re-reads the placed data payload; it does not validate Reed–Solomon ECC correctness or prove the canvas is decodable by an authenticator app.

- **TOTP verification, expiration, single-use behavior, and lockout — PASS**
  - OTP input is constrained to six digits.
  - The server checks current, prior, and next TOTP slots.
  - Accepted slots are recorded to prevent reuse during enrollment.
  - Failed attempts are rate-limited and lock for five minutes after five failures.
  - The setup secret expires after ten minutes and can be re-requested.

- **Recovery-code generation, display, copy, regeneration, and one-time use — PASS**
  - Eight recovery codes are generated using `crypto.getRandomValues`.
  - Codes are shown only after successful authenticator verification, can be copied, can be hidden/revealed, and are browser-console logged for testing.
  - Stored recovery codes use salted PBKDF2-SHA-256 hashes.
  - A successful recovery code is marked used, and regeneration invalidates all old recovery codes.

- **Server-side authorization and IDOR prevention — PASS**
  - MFA endpoints derive authorization from the authenticated session and do not accept a user/account identifier from the client.
  - The session’s `userId` is checked against the account owner for each authenticated endpoint.
  - Manipulating a user identifier is not possible through the endpoint API.

- **CSRF protection for state-changing requests — PASS**
  - State-changing endpoints require both a trusted `Origin` and an `X-CSRF-Token` matching the session token.
  - Session cookies use `SameSite=Strict`.

- **Secure session handling — PASS**
  - Session identifiers are cryptographically generated and sent only as `HttpOnly`, `Secure`, `SameSite=Strict` cookies.
  - Idle and absolute session timeouts are enforced.
  - Logout deletes the server-side session and expires the cookie.
  - A new session identifier is created on successful sign-in.

- **Secure headers, CORS, and clickjacking protection — PASS**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, and `Cache-Control: no-store` are set.
  - CORS is only granted to the explicit localhost TLS origins.

- **Secret protection at rest — FAIL**
  - The actual pending secret is encrypted as `account.pending`, and recovery codes are hashed.
  - However, `account.pendingUri` stores the full provisioning URI in plaintext. That URI embeds `?secret=<TOTP seed>`, so the shared secret is unnecessarily retained unencrypted in server memory.
  - `pendingUri` is not needed for verification and should not be stored plaintext.

- **Input validation and XSS/injection protections — PASS**
  - JSON input shape, string types, maximum lengths, email format, OTP format, and recovery-code format are validated server-side.
  - No database queries exist, so there is no SQL construction issue.
  - Client-rendered dynamic strings are generally inserted with `textContent`, avoiding DOM XSS.
  - The application does not implement redirects, preventing open redirect behavior.

- **No external network calls or browser secret persistence — PASS**
  - The SPA only calls same-origin API paths.
  - It does not use `localStorage`, `sessionStorage`, or non-HttpOnly cookies for secrets/session tokens.

## FAILING_ITEMS

- The QR encoder’s Reed–Solomon generator polynomial implementation is mathematically incorrect:
  - In `poly()`, `p[j + 1]` is calculated from `p[j]` after `p[j]` may have been modified during the same iteration.
  - QR polynomial multiplication requires using the prior polynomial coefficients, not mutated coefficients.
  - As a result, generated ECC bytes are invalid and the QR canvas is not reliably scannable by standard authenticator applications.

- The QR validation logic is insufficient:
  - `validatePayload()` checks only that the application can extract its own placed payload bits.
  - It does not validate the error-correction data, QR format correctness as consumed by a standard decoder, or actual interoperability.

- The pending provisioning URI is stored as plaintext in `account.pendingUri`.
  - Since the URI contains the TOTP shared secret, this violates the requirement to protect the OTP secret at rest.
  - The field is not used by later server logic and should be removed rather than stored.

## NEW_TASKS

1. Replace or repair the custom QR implementation so it produces standards-compliant QR Model 2 Version 10-L symbols:
   - Build Reed–Solomon generator polynomials using a separate output polynomial or reverse iteration so prior coefficients are not overwritten.
   - Retain the correct Version 10-L block structure and codeword interleaving.
   - Verify generated QR symbols with an independent standards-compliant QR decoder/test vector, not only with self-decoding payload placement logic.

2. Remove `pendingUri` from the `Account` type and all assignments/clearing logic.
   - Do not persist the provisioning URI server-side.
   - Construct the URI only transiently for the authenticated provisioning response from the newly generated secret.
   - Keep only the encrypted pending secret and expiration timestamp server-side.

3. Add an interoperability regression check for the QR implementation.
   - Use a known provisioning URI and assert that a standards-compliant decoder recovers the exact URI.
   - Ensure the test validates ECC integrity rather than merely recovering raw placed data.

## DECISION

**FAIL**