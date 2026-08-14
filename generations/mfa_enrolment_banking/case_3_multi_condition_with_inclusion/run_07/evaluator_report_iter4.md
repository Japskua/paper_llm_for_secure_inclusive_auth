## SUMMARY

The artifact is a single `app.ts` Bun HTTPS server with inline HTML, CSS, and vanilla JavaScript, and it implements most of the MFA flow, session checks, CSRF validation, rate limiting, secure cookies, TOTP verification, and mobile-oriented accessibility styling. However, it does not fully meet the requirements: the displayed “QR code” is not a valid QR code and cannot be scanned by authenticator apps; default academic-mode code reveal/logging is broken immediately after sign-in; and recovery codes cannot be regenerated/re-requested from the UI. These issues prevent acceptance.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no framework, bundler, compiler, or external assets**
  - The complete server, HTML, CSS, and browser JavaScript are contained in `app.ts`.
  - `Bun.serve` serves the SPA directly and uses `certs/cert.pem` and `certs/key.pem`.
  - No external network calls, dependencies, build tooling, or external asset URLs are present.

- **PASS — HTTPS/TLS and core security headers**
  - The Bun server is configured with TLS certificates.
  - Responses include HSTS, CSP, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, and `Permissions-Policy`.
  - Responses use `Cache-Control: no-store`.

- **PASS — Session and cookie protections**
  - Session cookies are configured with `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - Sessions have idle and absolute expiry checks.
  - A new session ID is generated at sign-in.
  - Logout invalidates the server-side session and clears cookies.

- **PASS — Server-side authorization and IDOR resistance**
  - MFA API routes derive the account from the authenticated server-side session rather than accepting a client-supplied account/user identifier.
  - Requests with missing, expired, manipulated, or unknown session IDs are rejected.
  - Stage checks prevent skipping forward through the enrolment process.

- **PASS — CSRF protections on state-changing authenticated MFA requests**
  - State-changing MFA endpoints check `X-CSRF-Token` against the server-side session token.
  - Cookies use `SameSite=Strict`.
  - Origin validation rejects origins other than `https://localhost:3000`.

- **PASS — Input validation and DOM output handling**
  - Email, password, and OTP input are validated server-side.
  - Browser UI uses DOM APIs and `textContent` rather than inserting server data through `innerHTML`.
  - No user-controlled redirect destination is accepted.

- **PASS — OTP lifecycle, replay prevention, and lockout controls**
  - Identity codes are hashed, expire, are single-use, and track failures.
  - TOTP verification accepts a narrow counter window and rejects previously accepted counters.
  - Failed identity and authenticator attempts are rate-limited and lock after repeated failures.
  - Identity-code resend has a server-side resend interval.

- **PASS — At-rest protection and secure random production values**
  - The authenticator secret is encrypted with AES-GCM before being stored in application state.
  - Recovery codes and identity codes are stored as hashes.
  - Production random values use `crypto.getRandomValues`.
  - Browser storage APIs are not used to persist session tokens, OTPs, seeds, or recovery codes.

- **FAIL — A usable, real QR-code provisioning option is provided**
  - `qrCanvas()` draws a deterministic “QR-style” image based on a hash-like process. It does not implement QR encoding, error correction, format data, or valid QR matrix construction.
  - Authenticator applications will not be able to scan it as an `otpauth://` URI.
  - The requirement explicitly requires a QR-code option when provisioning is offered. A decorative QR-like canvas is not sufficient.

- **FAIL — Default academic-mode mock code is shown/logged in the browser after a normal sign-in**
  - `ACADEMIC_MODE` defaults to `true`, and `/api/identity/send` returns the simulated identity code.
  - However, the client variable `academicMode` is only populated from `/api/me`, which is called before the user has authenticated.
  - `/api/signin` does not return `academicMode` or `testMode`. Therefore, immediately after signing in, `renderIdentity()` runs with `academicMode === false`.
  - When the identity code is sent, the UI neither logs `ACADEMIC SIMULATION identity code: ...` nor renders the reveal control, despite the server returning the code.
  - It only works after a page refresh, when `/api/me` can populate the mode flags.

- **FAIL — Recovery codes cannot be re-requested/regenerated from the UI**
  - Once recovery codes are created, `renderRecovery()` only shows the code list, copy button, and finish button.
  - The “Create recovery codes” action disappears, despite the server endpoint being capable of creating a new set while at the recovery stage.
  - This does not meet the requirement to let users “re-request codes without penalty,” and it omits a recovery-code regeneration path referenced by the security requirements.

- **PASS — Mobile accessibility and dyslexia-supportive presentation are substantially implemented**
  - The layout is constrained for mobile widths and includes responsive styling.
  - Font size, letter spacing, line height, short text, whitespace, examples, icons, large controls, clear progress indicators, and plain-language errors are present.
  - Inputs use suitable `autocomplete`, `inputmode`, and numeric OTP patterns.
  - There are no moving, flashing, or auto-updating UI elements.

- **PASS — Manual secret entry and clipboard support**
  - The setup secret is displayed and copyable.
  - The provisioning URI can be revealed and copied by selecting it.
  - Recovery codes are displayed and can be copied together.
  - Identity and authenticator code fields support browser one-time-code autofill.

## FAILING_ITEMS

- The provisioning canvas is not a valid QR code. It cannot be scanned by an authenticator application, so the claimed QR setup route is non-functional.
- The client does not receive or set `academicMode` and `testMode` after `/api/signin`.
  - As a result, in the normal default academic flow, the simulated identity code returned by `/api/identity/send` is not shown through the reveal control and is not logged in the browser console.
- The recovery-code screen does not provide a way to regenerate/re-request recovery codes after the first set is created.
- The UI does not clearly distinguish simulated/test-only secret/code exposure from production behavior after sign-in because its mode flags are stale until an authenticated `/api/me` request occurs.

## NEW_TASKS

1. Replace `qrCanvas()` with a standards-compliant QR encoder that produces a valid, scannable QR code for the returned `otpauth://` provisioning URI, implemented locally within `app.ts` and without external network assets.

2. Return `academicMode` and `testMode` from `/api/signin`, then assign those values in the sign-in success handler before calling `renderIdentity()`.

3. Verify the academic flow end-to-end without refreshing:
   - Sign in.
   - Send an identity code.
   - Confirm that the code is logged with `console.log` in the browser.
   - Confirm that the “Reveal simulated code” control is rendered when academic mode is enabled.

4. Add an explicit “Create new recovery codes” / “Replace recovery codes” control after recovery codes have been generated.
   - Keep it in the `recovery` stage.
   - Call the existing CSRF-protected `/api/recovery/create` endpoint.
   - Clearly warn that a newly generated set replaces the previous set.
   - Re-render and log the newly issued mock codes in test mode.

## DECISION

**FAIL**