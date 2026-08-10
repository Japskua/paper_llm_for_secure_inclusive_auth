## SUMMARY

The artifact is a single-file Bun application with a largely functional MFA enrolment flow, TLS configuration, server-side session ownership checks, CSRF checks, secure headers, encrypted authenticator seed storage, hashed recovery codes, and browser-side deterministic mock logging. However, it does not fully meet the requirements because the generated QR code is not a valid scannable QR implementation, no copy-to-clipboard controls are provided, authentication/recovery verification lockouts are not enforced, and deterministic recovery-code regeneration can reactivate previously used codes. Several required accessibility/retry/error-handling UX behaviours are also incomplete.

## FUNCTIONAL_CHECK

- **Single `app.ts` file containing Bun server, HTML, CSS, and vanilla browser JavaScript: PASS**
  - The application, server, inline styles, and client logic are all contained in the supplied `app.ts`.
  - No framework, bundler, compiler, external assets, or external network requests are used.

- **Bun HTTPS server using supplied TLS certificate paths: PASS**
  - `Bun.serve` is configured with `tls: { cert, key }`.
  - The certificate files are loaded from `certs/cert.pem` and `certs/key.pem`, as required.

- **Responsive mobile SPA and semantic/basic accessible structure: PASS**
  - The viewport meta tag, mobile-width layout, readable spacing, labels, `inputmode`, autocomplete values, live regions, and short screen-by-screen wording are present.
  - The UI uses a relatively legible sans-serif stack and avoids dense instructional paragraphs.

- **Sign-in, identity verification, authenticator setup, TOTP confirmation, and recovery-code acknowledgement flow: PASS**
  - The normal mock path can be completed using the supplied sign-in credentials, mock identity code, mock TOTP, and mock recovery codes.
  - Identity codes have expiry and single-use state.
  - Authenticator TOTP verification accepts a bounded clock window and tracks used time steps.
  - Recovery codes are hashed and deleted on use.

- **Browser mock behaviour and deterministic test values: PASS**
  - Mock identity code, provisioning URI, authenticator secret/current TOTP, and recovery codes are returned to the UI in academic mode.
  - The client calls browser `console.log` for these mock values, as explicitly required for testing.

- **Manual authenticator setup support: PARTIAL / FAIL**
  - A manual setup key is displayed and a manually entered authenticator code can be submitted.
  - However, there is no copy-to-clipboard control for the provisioning secret, provisioning URI, or recovery codes. This does not satisfy the requirement to offer copy-to-clipboard options so users do not need to transcribe long strings.

- **QR-code option is valid and scannable: FAIL**
  - The custom `qr()` function does not create a standards-compliant QR code.
  - It writes only data bytes and padding but does not generate or interleave required Reed–Solomon error-correction codewords. QR Version 10-L requires more raw codewords than the 274 data bytes written by this implementation.
  - The “QR verification” only performs `TextEncoder`/`TextDecoder` round-tripping of the original text; it does not decode or validate the canvas QR matrix.
  - As a result, ordinary authenticator apps/scanners cannot be relied upon to scan the displayed QR code.

- **Retry, hide/reveal, and re-request UX: FAIL**
  - Identity codes can be re-requested, and recovery codes can be regenerated.
  - However, the authenticator setup details cannot be hidden/revealed, copied, or explicitly re-requested after preparation without restarting the flow.
  - Sensitive long values are shown without an accessible hide/reveal control.
  - After requesting identity or authenticator details, the original primary request button remains visible alongside the verification primary action, creating more than one primary action on the screen.

- **Clear errors for every user-visible action: FAIL**
  - Several handlers lack error handling, including the recovery-code “I saved these codes” and “Make new codes” actions.
  - If a session expires, CSRF validation fails, or a network/API error occurs during these actions, the promise rejection is unhandled and the user does not receive the server’s clear actionable error message.

- **Server-side authorization and IDOR resistance: PASS**
  - Authenticated API operations obtain the user only from the HttpOnly session (`owner(r)`), not from a client-supplied user ID.
  - MFA state-modifying operations require the authenticated owner’s session.
  - There is no exposed user identifier parameter that can be manipulated for another account’s MFA state.

- **CSRF protections for state-changing requests: PASS**
  - Initial sign-in requires a boot CSRF value.
  - Authenticated POST requests require the session-bound CSRF token in `X-CSRF-Token`.
  - Session and boot cookies use `SameSite=Strict`.

- **Secure cookie and response-header configuration: PASS**
  - Session and boot cookies include `Secure`, `HttpOnly`, and `SameSite=Strict`.
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, referrer policy, and no-store cache controls are set.
  - CORS only permits the configured trusted origin.

- **Secret protection at rest and browser-storage restrictions: PASS**
  - The authenticator seed is AES-GCM encrypted before it is retained in the server-side user record.
  - Recovery codes are SHA-256 hashed with a process-secret pepper.
  - No secrets, OTPs, or session tokens are stored in `localStorage`, `sessionStorage`, URL parameters, or non-HttpOnly cookies.
  - Browser mock console output is intentionally present because the deliverable explicitly requires it in academic mock mode.

- **Input validation and XSS protections: PASS**
  - Email, password, six-digit OTP, and recovery-code formats are validated server-side.
  - UI-controlled dynamic output is generally escaped using the `esc()` helper before insertion via `innerHTML`.
  - Redirect handling is absent, so no open redirect is introduced.

- **Verification rate limiting and lockout: FAIL**
  - Identity verification correctly checks `blocked(u.guards.identity)`.
  - Authenticator verification calls `fail(u.guards.auth)` after failures but never checks `blocked(u.guards.auth)`, so an attacker can continue trying codes after five failed attempts.
  - Recovery-code verification calls `fail(u.guards.recovery)` but never checks `blocked(u.guards.recovery)`, so recovery-code guessing is likewise not locked out.
  - This fails the repeated-failed-verification rate-limit/lockout requirement.

- **Single-use recovery code enforcement across regeneration: FAIL**
  - In academic mode, `/api/recovery/regenerate` always reissues the same `fixtureCodes`.
  - A recovery code used through `/api/recovery/verify` is removed from the set, but regenerating codes recreates the same hash set and makes that exact previously used code valid again.
  - This violates the requirement that verification/recovery codes be single-use.

- **Session security: PASS**
  - Sign-in deletes the old session ID and creates a new random session ID, mitigating session fixation.
  - Idle and absolute session timeouts are implemented.
  - The logout endpoint invalidates the server-side session and clears the session cookie.

## FAILING_ITEMS

- The canvas QR generator is not a valid QR encoder because it omits Reed–Solomon error correction and QR codeword/interleaving rules. The displayed QR cannot be considered scannable by authenticator applications.
- The QR “verification” is not QR decoding or scanner validation; it only confirms that the input JavaScript string survives encode/decode unchanged.
- No copy-to-clipboard control exists for the manual authenticator key, provisioning URI, or recovery codes.
- Authenticator-code failures increment a guard but do not check whether the guard is locked before allowing further attempts.
- Recovery-code failures increment a guard but do not check whether the guard is locked before allowing further attempts.
- Recovery-code regeneration in mock mode reissues identical values, allowing a previously consumed recovery code to become valid again after regeneration.
- The recovery acknowledgement and regeneration click handlers do not catch API errors, so users may receive no visible error on session expiry, CSRF failure, or other API failures.
- The UI does not fully support the required hide/reveal and re-request behaviour for authenticator details.
- The identity/authenticator screens can show two simultaneous primary actions after a code/details request, contrary to the requirement for one clear primary action per screen.

## NEW_TASKS

1. Replace the custom `qr()` implementation with a standards-compliant, self-contained QR encoder that generates all required error-correction codewords, block interleaving, masking, and metadata for the provisioning URI; validate it using an actual QR decoder during development.
2. Add accessible copy-to-clipboard buttons for the provisioning URI/manual authenticator key and the displayed recovery-code set, with a plain confirmation message after copying.
3. Enforce `blocked(u.guards.auth)` before authenticator-code validation and enforce `blocked(u.guards.recovery)` before recovery-code validation; reset each relevant guard with `pass()` on successful verification.
4. Make regenerated mock recovery-code sets deterministic but distinct from prior sets, or retain a server-side set of all previously issued mock recovery-code hashes so a consumed value can never become valid again.
5. Add `try/catch` handling to recovery acknowledgement and regeneration UI handlers and render the server-provided actionable error through `msg(..., true)`.
6. Add hide/reveal and re-request controls for authenticator setup details, ensuring re-requesting invalidates the prior pending setup details where appropriate.
7. After an identity-code or authenticator-details request, demote the re-request action to a secondary control and keep only the verification/continuation action as the primary action.

## DECISION

**FAIL**