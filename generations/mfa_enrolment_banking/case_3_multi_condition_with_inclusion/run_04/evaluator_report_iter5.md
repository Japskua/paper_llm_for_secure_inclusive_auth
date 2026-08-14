## SUMMARY

The artifact is a single-file Bun HTTPS SPA with a well-structured MFA enrolment flow, responsive mobile UI, server-side sessions, CSRF checks, ownership checks, headers, encryption/hashing, rate limits, and simulated browser-side test values. However, it has a concrete logout/session-recovery functional defect, exposes sensitive values in an on-page log panel, uses permanently deterministic MFA secrets/recovery codes despite cryptographic-generation requirements, and only permits the `localhost` origin despite the supplied certificates also covering `127.0.0.1` and `::1`.

## FUNCTIONAL_CHECK

- **Single `app.ts` file containing Bun server, HTML, CSS, and vanilla browser JavaScript: PASS**
  - The complete application is contained in `app.ts`.
  - It uses Bun directly and does not require a framework, bundler, external assets, or compilation pipeline.

- **Bun HTTPS server uses the supplied certificate files: PASS**
  - The server reads `certs/cert.pem` and `certs/key.pem` and configures them through `Bun.serve({ tls: ... })`.

- **Mobile-responsive, readable MFA enrolment UI: PASS**
  - The page has a viewport meta tag, constrained mobile layout, large inputs/buttons, adequate spacing, readable font choices, and responsive styling.
  - The step indicator and primary action are prominent.

- **Dyslexia-inclusive UX: PASS**
  - Instructions are generally short and plain-language.
  - Inputs include examples and appropriate autocomplete attributes.
  - QR, copy-to-clipboard, download, reveal/hide, resend, and retry flows are provided.
  - There are no animations, flashing elements, or countdown displays.

- **Identity-code simulation and verification: PASS**
  - The simulated identity OTP is returned only after authenticated sign-in and logged in the browser.
  - Identity codes expire, are single-use, and have rate limiting/lockout behavior.
  - The UI supports requesting a replacement code.

- **Authenticator provisioning, manual setup, QR setup, and verification: PASS**
  - The application generates an `otpauth://` URI, offers a QR code, displays the Base32 secret manually, and provides copy controls.
  - Authenticator verification uses TOTP validation with a bounded validity window.
  - Setup attempts are rate-limited and setup details expire.

- **Backup recovery-code flow: PASS**
  - Recovery codes can be generated, displayed, hidden, copied, downloaded, regenerated, and verified.
  - Recovery codes are hashed before storage and removed after successful use.

- **Server-side authorization / IDOR prevention: PASS**
  - MFA management endpoints derive the account from the server-side session rather than accepting a client-supplied account ID.
  - `owner()` requires the authenticated session to belong to the expected account.

- **CSRF protection on state-changing actions: PASS**
  - State-changing requests require `x-csrf-token`.
  - The session token is HttpOnly and the CSRF token is maintained separately.

- **Secure session-cookie attributes: PASS**
  - Cookies use `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, and an expiry.
  - Session IDs are rotated after successful sign-in.

- **Security headers and clickjacking protection: PASS**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `frame-ancestors 'none'` are set.
  - Generic server errors are returned without stack traces.

- **Input validation and output safety: PASS**
  - OTP and recovery-code formats are validated server-side.
  - Account IDs are not accepted from client input.
  - User-controlled values are not inserted into HTML via `innerHTML`; the primary dynamic inserted values are server-controlled messages/counts.

- **Rate limiting, expiry, lockout, and session lifecycle: PASS**
  - Identity, authenticator, and recovery attempts enforce retry limits and temporary lockouts.
  - Identity and pending authenticator setup values expire.
  - Idle and absolute session expiration are implemented.

- **Logout and subsequent sign-in flow: FAIL**
  - After `/api/logout`, the client clears `csrf` and immediately renders `sign()`.
  - `sign()` does not request `/api/session` to create a new anonymous session and obtain a fresh CSRF token.
  - The next `/api/sign-in` request is sent with an empty CSRF token and no valid session, so it returns a 403 response until the user manually refreshes the page.

- **No exposure of OTP seeds, OTPs, backup codes, or tokens in logs: FAIL**
  - The browser-side `test()` function sends sensitive simulated values to both `console.log` and the visible `<pre id="logs">` panel.
  - The visible “Logs” panel displays authenticator secrets, provisioning URIs, identity OTPs, and recovery codes, unnecessarily exposing them in the UI after they have been generated.
  - Browser-console mock logging is explicitly required for testing, but displaying those secrets in a persistent in-page logging surface is not necessary to meet that requirement.

- **Cryptographically secure generation of OTP secrets and backup codes: FAIL**
  - `TEST_MODE` is hard-coded to `true`.
  - `base32()` always returns the same OTP secret, and `recoveryCodes()` always returns the same recovery-code set.
  - This means every session uses predictable, source-visible MFA credentials and recovery codes, violating the requirement to generate OTP secrets and backup codes using a cryptographically secure RNG.
  - A test mode may exist, but it must not be permanently enabled as the only runtime behavior.

- **Trusted-origin CORS / certificate-host compatibility: FAIL**
  - `TRUSTED_ORIGIN` permits only `https://localhost:3000`.
  - The stated certificates cover `localhost`, `127.0.0.1`, and `::1`; however, a POST from `https://127.0.0.1:3000` or `https://[::1]:3000` with an `Origin` header is rejected.
  - The application should explicitly allow the intended local TLS origins while continuing to reject all other origins.

## FAILING_ITEMS

- Logging out leaves the UI on a sign-in screen that cannot sign in again without a page refresh because no new anonymous session/CSRF token is obtained.
- The visible in-page “Logs” panel retains and displays OTPs, authenticator secrets, provisioning URIs, and recovery codes.
- MFA secrets and recovery codes are hard-coded deterministic values because `TEST_MODE` is permanently enabled.
- CORS/origin validation permits only `https://localhost:3000`, preventing use through the other certificate-covered local hosts (`127.0.0.1` and `::1`).

## NEW_TASKS

1. Update the client logout and expired-session handling so it calls `/api/session` and obtains a fresh anonymous-session CSRF token before rendering a usable sign-in form.
2. Remove sensitive OTPs, provisioning URIs, Base32 secrets, and recovery codes from the visible in-page log panel; retain required test-only browser `console.log` output without persisting these values in the document.
3. Make secure random generation the default runtime behavior for authenticator secrets and recovery codes, and isolate deterministic test fixtures behind an explicit non-production test-mode configuration rather than `const TEST_MODE = true`.
4. Replace the single `TRUSTED_ORIGIN` check with a strict allow-list containing `https://localhost:3000`, `https://127.0.0.1:3000`, and `https://[::1]:3000`, and return the matching permitted origin in CORS responses.

## DECISION

FAIL