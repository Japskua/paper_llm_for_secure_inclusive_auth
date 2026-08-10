## SUMMARY

The artifact is a single-file Bun TLS application with a functional sign-in, identity check, TOTP setup, recovery-code generation, CSRF/session controls, secure headers, and accessible mobile-oriented UI. However, it does not fully meet the requirements because the displayed “QR code” is not a standards-compliant QR code and cannot be scanned by an authenticator app. There are also UX gaps around preserving/revealing setup details and confirming certain actions.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with inline HTML, CSS, and browser JavaScript**
  - All application code is in `app.ts`.
  - It uses `Bun.serve` directly and does not require a bundler, framework, external asset, or compilation step.
  - TLS certificates are read from the required `certs/cert.pem` and `certs/key.pem` paths.

- **PASS — HTTPS/TLS and security response headers**
  - The server is configured with TLS.
  - Responses include CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `frame-ancestors 'none'`.
  - The CSP uses per-page nonces for the inline style and script.

- **PASS — Session and authorization protections**
  - MFA endpoints derive the user from the server-side session rather than accepting a user ID from the client.
  - There is no apparent IDOR parameter that could be manipulated to access another user’s MFA state.
  - Sessions have idle and absolute expiration checks, are regenerated on sign-in, and are invalidated by `/api/logout`.

- **PASS — Cookie and CSRF protections**
  - Session and bootstrap cookies use `Secure`, `HttpOnly`, `SameSite=Strict`, and `Path=/`.
  - State-changing endpoints require an `X-CSRF-Token`.
  - The sign-in route uses a protected bootstrap CSRF value, while authenticated routes use a session-bound CSRF token.

- **PASS — CORS and origin restrictions**
  - CORS is restricted to configured trusted HTTPS loopback/application origins.
  - Requests with an untrusted `Origin` are rejected.
  - Credentialed CORS responses are only emitted for trusted origins.

- **PASS — OTP, recovery-code, expiry, and rate-limit logic**
  - Identity codes are time-bound and single-use.
  - TOTP verification accepts a limited clock window and prevents reuse of an accepted TOTP time step.
  - Recovery codes are one-use and expire.
  - Failed identity, authenticator, and recovery-code verifications are rate-limited with a lockout after repeated failures.

- **PASS — At-rest protection of MFA material**
  - Authenticator seeds are AES-GCM encrypted before storage in the in-memory user object.
  - Passwords, OTP verification values, and recovery codes are hashed before storage.
  - Cryptographic random generation is used outside the explicitly configured academic mock mode.

- **PASS — Input validation and output encoding**
  - Email, OTP, and recovery-code formats are validated server-side.
  - The UI escapes values before dynamically inserting them into HTML.
  - No SQL/database layer is used, so no unparameterized query issue exists.

- **PASS — Mobile and dyslexia-conscious UI basics**
  - The page includes a mobile viewport meta tag and a constrained mobile-friendly layout.
  - It uses generous spacing, plain wording, visible step/progress indicators, examples for expected code formats, `autocomplete` hints, and `inputmode="numeric"` for codes.
  - It avoids auto-updating, flashing, or animated content.

- **PASS — Browser mock behavior**
  - Academic mock identity codes, TOTP values, provisioning values, and recovery codes are shown in the UI and logged through browser-side `console.log`.
  - The mock values can be used to complete the verification flow.

- **FAIL — A real QR-code option is not implemented**
  - The `qr(canvas, text)` function draws pseudorandom pixels and finder-like squares, but does not generate a valid QR encoding of `provisioningUri`.
  - Authenticator applications will not be able to scan this canvas to provision the TOTP secret.
  - This fails the requirement to offer a QR-code option for authenticator provisioning.

- **FAIL — Authenticator setup details cannot be safely re-shown without replacing them**
  - The UI says: “You may show the link or manual key again without making new details.”
  - In practice, after leaving or re-rendering the setup view, the only available action is “Prepare authenticator details,” which calls `/api/authenticator/setup` again and generates/replaces the secret.
  - This conflicts with the stated predictable/retryable flow and the requirement to allow users to reveal/hide/re-request information without penalty.

- **FAIL — Some action confirmations are lost immediately**
  - On recovery-code regeneration, the code calls `message(...)` and then immediately calls `render()`.
  - `render()` begins by clearing `$("msg").innerHTML`, so the user never sees the confirmation: “New recovery codes were made. Earlier codes no longer work.”
  - This violates the requirement to plainly confirm what happened after each action.

- **PARTIAL/FAIL — “One clear primary action” and recovery-code flow clarity**
  - The recovery screen presents both “I saved these codes” and “Make new codes.” The second button is styled secondary, which helps, but there is no durable status after regeneration because the confirmation is cleared.
  - The primary path is therefore less clear than required after replacement codes are generated.

## FAILING_ITEMS

- The canvas renderer is not a valid QR-code encoder. It creates decorative pseudorandom pixels rather than an authenticator-scannable QR code containing the `otpauth://` provisioning URI.
- The UI claims users can show provisioning details again without generating new details, but the implementation regenerates the server-side secret whenever “Prepare authenticator details” is used again.
- Recovery-code regeneration confirmation is erased immediately because `render()` clears the message area after `message(...)` is called.
- The recovery-code replacement flow does not persist a visible confirmation/status explaining that prior codes were invalidated and the displayed set is the current replacement set.

## NEW_TASKS

1. Replace the custom `qr()` pseudorandom canvas renderer with an embedded, standards-compliant QR-code encoder implemented in vanilla browser JavaScript, and encode the exact `provisioningUri` into the QR code.
2. Preserve current authenticator provisioning details in the client view while the setup step is active, and add explicit “Hide details” / “Show details again” controls that do not call `/api/authenticator/setup` or rotate the secret.
3. Separate “Generate new authenticator details” from “Show existing details,” with clear warning text before any action that invalidates previous provisioning details.
4. Change recovery-code regeneration handling so the success message survives rendering, for example by storing a pending status message in state and rendering it after the recovery screen is rebuilt.
5. Add durable recovery-screen status text after regeneration that states new codes are displayed and earlier recovery codes no longer work.

## DECISION

**FAIL**