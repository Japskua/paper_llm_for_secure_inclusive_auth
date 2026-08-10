## SUMMARY

The artifact is a single `app.ts` Bun application with inline HTML, CSS, and vanilla browser JavaScript. It implements most of the MFA flow, mobile-focused accessibility design, server-side session ownership checks, CSRF checks, TLS configuration, headers, secure cookies, rate limiting, encrypted TOTP seed storage, and hashed recovery codes. However, it does not fully meet the requirements because the custom QR encoder does not follow the required QR data-placement traversal and therefore cannot reliably produce a scannable QR code. In addition, refreshing or re-entering an in-progress authenticator setup loses the provisioning details in the client UI, leaving an empty/invalid setup screen.

## FUNCTIONAL_CHECK

- **Single-file Bun server with HTML, CSS, and vanilla browser JavaScript: PASS**
  - The complete application is contained in one `app.ts`.
  - It uses `Bun.serve`, inline HTML/CSS/JS, and no framework, bundler, compiler, or external assets.

- **TLS/HTTPS configuration using supplied mkcert certificate paths: PASS**
  - The Bun server is configured with `certs/cert.pem` and `certs/key.pem`.
  - The server advertises an HTTPS URL and uses HSTS.

- **Responsive, legible mobile web UI: PASS**
  - The page has a mobile viewport meta tag, constrained mobile content width, responsive CSS, large form controls, readable line height, spacing, and mobile-specific sizing adjustments.
  - Typography avoids italics and uses common legible fonts with increased letter spacing.

- **Dyslexia-inclusive UX and plain-language guidance: PASS**
  - Instructions are short, use examples for email and code fields, provide clear step labels, include icons, provide help `<details>` on each step, and use clear error messages with corrective actions.
  - There are no moving, flashing, or auto-updating UI elements.
  - The UI offers demo-fill buttons, copy buttons, QR/manual provisioning options, and retry/regeneration paths.

- **Working simulated identity-code verification: PASS**
  - The identity code is generated with `crypto.getRandomValues`, time-bound, hashed server-side, single-use, and returned only for the intended demo UI flow.
  - The browser logs the mock identity code with `console.log`.
  - Verification has input validation, expiry, lockout, and clear errors.

- **Working TOTP authenticator provisioning and verification: PASS, except QR delivery**
  - A TOTP seed is generated using cryptographic RNG, encrypted with AES-GCM in server memory, and verified using TOTP logic.
  - OTPs are accepted only while provisioning is valid, have a limited verification window, and are prevented from reuse through hashed used-code tracking.
  - The current mock OTP is returned to the UI and logged in the browser console.
  - Manual secret and provisioning URI copying are available.
  - **However, the QR-code option itself is not reliable; see failing item below.**

- **QR code option is usable/scannable: FAIL**
  - The custom `qrSvg()` implementation does not follow the standard QR zig-zag data placement algorithm.
  - In particular, the placement logic always writes populated data-column pairs bottom-to-top rather than alternating direction for each pair, and it does not correctly handle the timing-pattern column traversal.
  - A QR scanner reads module bits using the standard alternating traversal, so this output will not reliably decode the provisioning URI.
  - Since the UI explicitly presents this as a “Scannable QR code,” this is a functional failure.

- **Manual submission/copy alternatives for provisioning secrets and codes: PASS**
  - The setup screen provides a copyable manual secret and a copyable provisioning URI.
  - The OTP verification field supports direct manual OTP entry and browser OTP autofill.
  - Recovery codes can be copied as a group.

- **Provisioning details remain usable after refresh/re-entry: FAIL**
  - `status()` sets `s.screen = "setup"` whenever the account has passed identity verification but has not enabled MFA.
  - It does not call `/api/authenticator/provision` in that case.
  - After a page refresh, a re-login, or a restored session during setup, `s.secret` and `s.uri` remain empty in browser memory.
  - The setup screen then renders an empty manual secret and generates a QR code for an empty string rather than showing valid provisioning information.
  - This prevents reliable continuation/retry of the enrolment flow.

- **Recovery-code generation, confirmation, and one-time consumption: PASS**
  - Eight recovery codes are generated using cryptographic randomness.
  - Only hashes are retained server-side.
  - Codes are returned to the UI and logged in the browser console as required for the mock.
  - Confirmation is required before the final settings screen.
  - Recovery-code verification consumes a successful code and includes validation and lockout.

- **Server-side authorization / no IDOR on MFA endpoints: PASS**
  - Protected endpoints derive the account from the HttpOnly session cookie and never accept a client-controlled user/account identifier.
  - Session lookup validates the referenced account before granting access.
  - MFA state changes are scoped to `s.userId`.

- **CSRF protection on state-changing authenticated endpoints: PASS**
  - Authenticated non-GET API requests require an `X-CSRF-Token` matching the server-side session token.
  - State-changing requests also require a trusted configured Origin.
  - Session cookies use `SameSite=Strict`.

- **Secure headers and restricted CORS: PASS**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and CSP `frame-ancestors 'none'` are set.
  - CORS is restricted to explicit localhost HTTPS origins.
  - CSP uses a per-page nonce for inline style and script content.

- **Secure session handling: PASS**
  - Cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - Sessions have idle and absolute expiry checks.
  - Existing sessions for the account are removed during sign-in, mitigating fixation/concurrent stale-session concerns.
  - Logout invalidates the server session and clears the cookie.

- **Rate limiting, lockout, and single-use/time-bound codes: PASS**
  - Sign-in, identity verification, TOTP verification, and recovery-code verification have failure counters and timed lockouts.
  - Identity codes have expiry and one-time use.
  - TOTP provisioning has an expiry and accepted TOTP values are recorded to prevent reuse.
  - Recovery codes are deleted after successful use.

- **No secrets in server logs, URLs, browser storage, or non-HttpOnly cookies: PASS**
  - No secret-bearing URLs or client storage are used.
  - The server does not log OTP seeds, OTPs, recovery codes, or session tokens.
  - Mock OTPs and recovery codes are intentionally logged only in the browser console, as explicitly required.

- **Input validation and output escaping: PASS**
  - Server-side validation exists for emails, credentials, numeric codes, and recovery-code format.
  - The client escapes dynamic values before inserting them into HTML.
  - No database queries are used, so SQL injection is not applicable to this in-memory mock.

## FAILING_ITEMS

- **The QR code generator is not standards-compliant and is unlikely to produce a scannable QR code.**
  - `qrSvg()` writes QR payload bits with incorrect module traversal.
  - QR data placement must alternate vertical direction between each two-column stripe; this implementation does not do so for the actually populated pass.
  - It also fails to correctly implement standard traversal around the timing-pattern column.
  - The result cannot be accepted as a working QR-code enrolment option.

- **Authenticator provisioning cannot reliably resume after a refresh, re-login, or restored authenticated session.**
  - The browser state holds `s.secret` and `s.uri` only in memory.
  - `/api/mfa/status` identifies the setup stage but does not return provisioning data.
  - The client does not call `/api/authenticator/provision` when it restores the setup screen.
  - Therefore the setup screen may show blank manual details and an empty QR code.

- **The provisioning URI is always visibly rendered, even when the manual secret is “Hidden for privacy.”**
  - The provisioning URI contains the same TOTP secret as the manual secret.
  - Hiding only `s.secret` does not meaningfully hide the credential while the URI remains fully visible.
  - This conflicts with the stated reveal/hide support for sensitive setup details.

## NEW_TASKS

1. Replace the custom `qrSvg()` encoder with a verified standards-compliant QR Model 2 encoder implemented locally in `app.ts`, or correct its QR data placement, masking, reserved modules, error correction, and alternating zig-zag traversal so that authenticator apps can scan the generated `otpauth://` URI.

2. Make authenticator setup resumable:
   - Update the authenticated status/setup bootstrap flow so that when identity is verified and MFA is not enabled, the client obtains valid provisioning details from the server before rendering the setup screen.
   - Ensure this works after page refresh, re-login, and session restoration.
   - Preserve the existing server-side provisioning expiry semantics and show a clear “request fresh setup details” action if the prior provisioning window has expired.

3. Apply reveal/hide behavior consistently to all secret-bearing provisioning material:
   - Hide the provisioning URI by default when the manual secret is hidden, or avoid rendering it until the user explicitly reveals it.
   - Keep copy actions available only after an explicit reveal/confirmation, while retaining the accessible QR/manual-copy alternatives.

## DECISION

**FAIL**