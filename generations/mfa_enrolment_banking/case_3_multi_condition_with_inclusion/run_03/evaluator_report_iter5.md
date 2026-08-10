## SUMMARY

The artifact is a strong single-file Bun HTTPS SPA with substantial security controls, mobile-focused UI, CSRF/session handling, encrypted/hash-stored MFA data, rate limiting, and accessible plain-language flow design. However, it does not fully meet the functional mock-delivery requirement in its default configuration, and its hand-written QR encoder contains invalid QR metadata placement/generation logic that makes the QR provisioning option unreliable. These defects prevent acceptance.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with inline HTML, CSS, and browser JavaScript**
  - The complete server and SPA are contained in `app.ts`.
  - Bun directly serves the page with `Bun.serve`; there are no frameworks, build tools, bundlers, or external assets.
  - TLS certificate/key files are loaded from the required `certs/cert.pem` and `certs/key.pem` paths.

- **PASS — HTTPS and security response headers**
  - The server is TLS-only through Bun’s `tls` configuration.
  - Responses include CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, cache prevention, and CSP `frame-ancestors 'none'`.

- **PASS — Secure session and authorization controls**
  - Session cookies are `Secure`, `HttpOnly`, and `SameSite=Strict`.
  - Server-side session ownership is enforced for authenticated MFA endpoints.
  - The user ID is derived exclusively from the server-side session, preventing client-supplied user-ID manipulation/IDOR.
  - Session rotation occurs on sign-in, idle and absolute expiry are enforced, and logout invalidates the server-side session.

- **PASS — CSRF protection and same-origin protections**
  - State-changing requests require a CSRF token.
  - A temporary boot token protects sign-in before an authenticated session exists.
  - CORS is restricted to the configured exact origin, and cross-origin requests are rejected.

- **PASS — MFA secret, OTP, and recovery-code security model**
  - Authenticator secrets are generated using cryptographic randomness and encrypted with AES-GCM before storage.
  - Identity codes and recovery codes are stored as hashes rather than plaintext.
  - Identity codes are time-bound and single-use.
  - TOTP codes are checked against limited time windows and a used TOTP time step cannot be reused.
  - Recovery codes are consumed on successful verification.

- **PASS — Verification rate limiting and lockout**
  - Identity, authenticator, and recovery-code verification paths track failed attempts.
  - Five failures trigger a 15-minute lockout.
  - Responses provide specific, user-oriented recovery guidance.

- **PASS — Input validation and XSS protections**
  - Email, password, OTP, and recovery-code inputs are validated server-side.
  - User-controlled values are not inserted unsafely into HTML.
  - Client-side recovery-code rendering uses escaping.
  - No redirects are accepted from user input.

- **PASS — Mobile and dyslexia-aware UX**
  - The layout is responsive and constrained for small mobile widths.
  - Typography, spacing, line-height, plain-language labels, examples, visual progress, and large buttons support readability.
  - There are no moving, flashing, or countdown-based UI elements.
  - The flow includes retry/regenerate controls and clear messages after actions.
  - Authenticator setup provides both QR and manual secret-copy methods.
  - Copy-to-clipboard fallback fields support manual browser copy when the Clipboard API is unavailable.

- **FAIL — Simulated OTP delivery and verification work in the default application configuration**
  - `MFA_TEST_FIXTURES` defaults to `false`.
  - In that default state, `/api/identity/request` generates a random code but neither returns it to the browser nor logs it in the browser.
  - The UI says that a check code is “ready,” but there is no actual email/SMS delivery implementation and no usable simulation path.
  - Therefore, a user running the application normally cannot obtain the identity code and cannot complete MFA enrolment.
  - The deterministic browser-console mock path exists only when the server is started with `MFA_TEST_FIXTURES=1`, but the requirements do not make successful use of the app conditional on an undocumented environment switch.

- **FAIL — QR provisioning option is reliably functional**
  - The custom QR encoder has invalid version-information BCH generation:
    - The version BCH calculation iterates the unshifted version bits incorrectly:
      ```js
      let value=V,bch=V;
      for(let i=0;i<12;i++) if((bch>>>i)&1) bch^=0x1f25<<(11-i);
      ```
    - This is not the required polynomial-division process for QR Version 10 version information.
  - The second format-information copy is also written to incorrect coordinates:
    ```js
    m[8][14-i-1]=bit;
    ```
    - At `i = 14`, this writes to `m[8][-1]`.
    - It skips required QR format modules, corrupting one of the redundant format-information areas.
  - Although some QR readers may recover by inferring version from symbol size or using the other metadata copy, this is not reliable and does not meet the requirement that the QR option function correctly.

- **PASS — Internal navigation/state transitions are implemented**
  - The SPA step transitions for sign-in, identity verification, authenticator setup, recovery-code saving, completion, and recovery-code testing are wired through working client-side event handlers.
  - There are no dead internal hyperlinks.

## FAILING_ITEMS

- The default application cannot complete identity verification because the generated identity code is neither delivered nor exposed through the required browser-console mock mechanism unless `MFA_TEST_FIXTURES=1` is manually supplied.
- The mock behavior required by the deliverable is conditional on an environment variable and is not available in the default app behavior.
- The QR encoder produces invalid Version 10 QR version information due to incorrect BCH remainder generation.
- The QR encoder writes part of the second format-information copy to invalid/wrong coordinates, including `m[8][-1]`, making the QR symbol non-compliant and potentially unscannable.

## NEW_TASKS

1. Make the academic mock delivery flow usable by default, or clearly implement a default browser-side deterministic mock mode that returns and `console.log`s the identity code, provisioning test code, and recovery codes while retaining a separately configurable production-safe mode.
2. Ensure the identity-code request UI provides a complete simulated delivery path: after requesting a code, the user must be able to obtain the deterministic mock value through the browser console and successfully verify it without relying on an unstated external service.
3. Replace the custom QR Version 10 metadata generation with a verified standards-compliant implementation of QR format and version BCH encoding, including correct bit ordering and polynomial division.
4. Correct QR format-information placement coordinates for both redundant metadata copies and add a deterministic test that verifies generated provisioning QR codes can be decoded to the exact `otpauth://` URI.

## DECISION

FAIL