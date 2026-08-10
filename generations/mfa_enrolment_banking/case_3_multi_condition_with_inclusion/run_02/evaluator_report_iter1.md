## SUMMARY

The artifact is a single-file Bun HTTPS SPA with strong coverage of headers, session cookies, CSRF checks, server-side authorization, encrypted OTP seed storage, hashed backup codes, and mobile-oriented UI styling. However, it is not functional as delivered because all client button event handlers are registered for `"Click"` rather than the browser event `"click"`. In addition, the displayed QR-style canvas is not a valid scannable OTP provisioning QR code, and OTP replay handling is flawed for codes accepted from the previous time window. These issues prevent acceptance.

## FUNCTIONAL_CHECK

- **FAIL — Sign-in, identity verification, provisioning, OTP verification, backup-code use, regeneration, and logout must function in the browser.**  
  The `el()` helper registers handlers using `node.addEventListener(k.slice(2), v)`. For properties such as `onClick`, this produces the event name `"Click"` rather than `"click"`. DOM event names are case-sensitive, so all button click handlers fail to run. The user cannot proceed past any screen.

- **FAIL — QR-code provisioning option must work.**  
  `drawQR()` creates a deterministic random-looking grid from the provisioning URI. It is labelled `"Provisioning QR-style code"` and does not encode the `otpauth://` URI according to QR standards. An authenticator app cannot scan and provision from it. The manual secret is available, but the offered QR option itself is non-functional.

- **FAIL — The flow must set up a working time-based OTP authenticator.**  
  The provisioning URI represents normal TOTP provisioning, but server verification uses a custom hash of `secret:fiveMinuteSlot:academic-mfa-demo`, not the standard TOTP algorithm an authenticator app would generate from the supplied `otpauth://` URI. Therefore, codes from a real authenticator app configured with the manual secret or a corrected QR code would not verify.

- **FAIL — OTPs must be single-use and time-bound.**  
  OTPs are time-bound, but prior-window codes can be replayed. In `/api/mfa/verify`, a valid code for `slot - 1` is accepted, while replay prevention checks and records only `account.otpUsedSlots.has(slot)` / `add(slot)`. A code used in slot `N` can be submitted again in slot `N + 1` as a prior-slot code because slot `N + 1` has not yet been marked used.

- **FAIL — Repeated failed verification attempts must be rate-limited and locked out.**  
  Authenticator OTP and recovery-code attempts have a five-attempt lockout, but the identity verification endpoint (`/api/identity`) has no failure counter, rate limit, or lockout. The static identity code can be guessed indefinitely.

- **PASS — MFA endpoints enforce server-side session authorization and do not trust user-supplied account IDs.**  
  Protected routes use `authorized()` or `csrfAuthorized()`, sessions are server-side, and the account ID is derived from the session rather than client input. There is no user identifier parameter that can be manipulated for IDOR.

- **PASS — State-changing endpoints have CSRF protection.**  
  POST mutation routes use `csrfAuthorized()`, which requires both a trusted `Origin` and a matching session-bound `X-CSRF-Token`.

- **PASS — Session cookies use appropriate browser attributes.**  
  The session cookie is set with `HttpOnly`, `Secure`, `SameSite=Strict`, and `Path=/`. Session idle and absolute expiry are checked server-side, a fresh session ID is generated on sign-in, and logout removes the server session.

- **PASS — Security response headers and restrictive CORS are implemented.**  
  CSP with nonce-based scripts/styles, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, no-store caching, and an explicit trusted-origin CORS allow-list are present.

- **PASS — OTP secret and backup code storage use cryptographic protection.**  
  OTP secrets are AES-GCM encrypted using a non-extractable generated key; recovery codes use cryptographically random values and PBKDF2-SHA-256 hashes with individual salts.

- **PASS — Input validation and output handling are generally safe.**  
  Server inputs have type, length, and format validation. Client-rendered dynamic values use `textContent` through the element helper, avoiding direct HTML injection. No open redirect capability is present.

- **PASS — The UI generally follows mobile and dyslexia-inclusive presentation requirements.**  
  It uses responsive single-column layout, adequate spacing, plain wording, examples for inputs, copy controls, browser autofill attributes, no motion or auto-updating content, and clear status/error messages.

- **PASS — Single-file and zero-compilation compliance.**  
  The application is contained in `app.ts`, uses Bun directly, embeds HTML/CSS/browser JavaScript, does not use frameworks, bundlers, external assets, or external network calls, and configures Bun TLS using `certs/cert.pem` and `certs/key.pem`.

## FAILING_ITEMS

- The client-side event binding helper creates `"Click"` event listeners instead of `"click"` listeners, so every button-driven flow action is inoperative.
- The advertised QR code is only a random visual pattern, not a valid QR encoding of the provisioning URI.
- The server’s custom OTP calculation is incompatible with standard authenticator applications and the supplied `otpauth://` provisioning URI.
- Previous-window OTPs can be replayed once in the following time window because replay tracking stores/checks the current slot rather than the slot that actually matched.
- `/api/identity` has unlimited failed attempts and no lockout, violating the failed-verification rate-limit/lockout requirement.
- The in-page “Logs” panel renders sensitive mock provisioning values, OTPs, and backup codes into the visible application DOM. Testing output required by the brief should remain in the browser console; the persistent visible diagnostic panel is unnecessary exposure.

## NEW_TASKS

1. Update the `el()` helper to normalize event names, for example: `node.addEventListener(k.slice(2).toLowerCase(), v)`, and verify every primary, secondary, copy, navigation, and logout action works.
2. Replace `drawQR()` with a real, standards-compliant QR encoder implemented inline in `app.ts`, encoding the returned `otpauth://` URI.
3. Implement standard RFC 6238 TOTP verification compatible with the generated `otpauth://totp/...` URI, including a declared period/digits/algorithm in the URI if non-default values are used.
4. Correct OTP single-use enforcement by determining the matched time slot (`slot` or `slot - 1`) and checking/recording that matched slot, rather than always checking/recording the current slot.
5. Add server-side failed-attempt counting and a timed lockout for `/api/identity`, using the same clear non-blaming error style as OTP and recovery-code lockouts.
6. Remove the rendered `logsPanel()` diagnostic UI or ensure it never displays OTPs, setup secrets, recovery codes, or session-related values; retain only the explicitly required browser `console.log` test output.

## DECISION

FAIL