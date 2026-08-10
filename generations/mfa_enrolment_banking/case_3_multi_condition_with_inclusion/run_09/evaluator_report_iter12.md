## SUMMARY

The artifact is a single `app.ts` Bun HTTPS application with a responsive vanilla HTML/CSS/JavaScript MFA flow. It implements many important controls correctly: server-side session ownership, CSRF validation, secure cookies, TLS, security headers, OTP/recovery-code generation and protection, verification, lockouts, and browser-side mock logging. However, it does not fully meet the functional and UX requirements because recovery codes disappear after a refresh without an adequate recovery-state UI, CSP blocks the inline style updates needed for the progress indicator, and the mock values are not deterministic as required. Therefore the artifact cannot be accepted as-is.

## FUNCTIONAL_CHECK

- **FAIL — Single-file Bun application with no frameworks, bundlers, external assets, or network calls**
  - The entire application is contained in `app.ts`, uses Bun directly, embeds HTML/CSS/client JavaScript, and does not reference external assets or make external network calls.
  - However, full acceptance fails because other functional and UX requirements are not met.

- **PASS — Bun HTTPS server uses the supplied certificate paths**
  - `Bun.serve` is configured with:
    - `cert: Bun.file("certs/cert.pem")`
    - `key: Bun.file("certs/key.pem")`
  - The server is configured to serve HTTPS on port 3000.

- **PASS — Mobile-responsive, legible, plain-language MFA interface**
  - The UI uses a narrow mobile shell (`max-width: 540px`), responsive CSS, large touch targets, readable font sizing, generous line spacing, plain-language labels, examples, icons, and no moving/flashing elements.
  - It includes `autocomplete`, `inputmode`, and one-time-code support for appropriate inputs.

- **FAIL — Current step and progress must be visually prominent and accurate**
  - The page uses inline `style` attributes for the initial progress width and count positioning:
    - `style="float:right"`
    - `style="width:16.67%"`
  - The CSP only allows styles carrying the generated nonce:
    - `style-src 'nonce-${nonce}'`
  - Inline style attributes do not carry that nonce and are blocked by a compliant CSP. Additionally, subsequent `progress.style.width = ...` updates are inline style updates and are also blocked under this policy.
  - Since `.bar span` is a block element without a permitted width declaration, it defaults to filling the available width. The progress bar can therefore appear complete at every step rather than reflecting the current step.

- **FAIL — Recovery-code flow remains usable after refresh and supports re-requesting/revealing codes**
  - Recovery codes are intentionally held only in browser memory (`codes=[]`) and are not persisted, which is correct from a browser-storage perspective.
  - But after a page refresh during the `"recovery"` stage, `/api/state` returns only the stage; it does not return recovery codes, and the client renders an empty `<ul class="codes">`.
  - The UI still presents “I have saved my codes,” even though no codes are shown. A user who refreshed before copying/saving cannot see the issued codes and receives no explicit explanation or clear primary recovery action.
  - Although “Make new codes” exists, the flow should explicitly explain that the original codes can no longer be displayed and guide the user to generate replacement codes before completion.

- **PASS — Authenticator setup supports QR and manual/copyable setup**
  - The setup endpoint returns a provisioning URI and Base32 secret to the authenticated session owner.
  - The UI provides a generated QR code, reveal/hide control for the manual secret, and copy controls for both the secret and provisioning URI.
  - Users can request fresh setup details if needed.

- **PASS — Identity, authenticator, and recovery-code verification work server-side**
  - Identity codes are generated, hashed with HMAC, time-bound, single-use, and invalidated on resend.
  - Authenticator verification uses TOTP derived from an encrypted Base32 seed.
  - Recovery codes are generated with cryptographic randomness, stored as PBKDF2 hashes with salts, and become unusable after successful verification.
  - Incorrect attempts are rate-limited/locked after repeated failures.

- **FAIL — Mock values must be deterministic**
  - The stated requirement calls for simulated OTP delivery, authenticator provisioning, and verification with deterministic mock values.
  - This implementation generates identity codes with secure random values, authenticator secrets with random Base32 values, time-dependent TOTP values, and random recovery codes.
  - These are secure and functional, but not deterministic/reproducible test mocks. The browser console values change between sessions and, for TOTP, with time.

- **PASS — Required browser-side test logging is implemented**
  - The client logs the identity code, authenticator OTP, and recovery codes with `console.log`.
  - These values are received by the browser UI and logged from browser-side JavaScript, rather than being written to server logs.

- **PASS — Broken access control protections**
  - Authenticated MFA endpoints obtain the session from the HttpOnly cookie and use the session-bound account state rather than a client-provided user identifier.
  - There is no user ID parameter that can be manipulated for IDOR.
  - State-changing requests require a session-specific CSRF token and an allow-listed `Origin`.
  - MFA state and secrets are only accessible through the authenticated owner’s session.

- **PASS — Secure session handling**
  - Cookies are set with `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - Sessions have idle and absolute expiry checks.
  - The session identifier is replaced upon successful sign-in.
  - Logout deletes the server session and expires the cookie.

- **PASS — Security headers and clickjacking protection**
  - Responses include HSTS, CSP, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, no-store cache control, and a restrictive Permissions Policy.
  - Generic errors are returned from the top-level server handler rather than stack traces.

- **PASS — OTP seed and recovery-code protection at rest**
  - The OTP seed is encrypted with AES-GCM before being retained in the server-side session.
  - Recovery codes are generated with `crypto.getRandomValues` and stored as salted PBKDF2 hashes.
  - Secrets, codes, and session tokens are not stored in `localStorage`, `sessionStorage`, or non-HttpOnly cookies.

- **PASS — Input validation, XSS handling, and redirect safety**
  - Inputs are constrained by maximum lengths and format validation.
  - There are no database queries or redirects.
  - Dynamic sensitive values are inserted using `textContent` where applicable, and server messages are static controlled strings.

## FAILING_ITEMS

- The CSP blocks the inline style attributes and JavaScript inline style mutations used to render/update the step progress bar. This makes the visible progress indicator inaccurate.
- Refreshing during the recovery-code stage produces an empty recovery-code list with no clear explanation that codes cannot be re-shown and must be regenerated.
- The implementation uses random and time-dependent values for all mock codes instead of deterministic mock values required for predictable evaluation/testing.
- The recovery stage permits completion even after refresh when no recovery codes are visible, undermining the requirement that the user securely save the codes before finishing.

## NEW_TASKS

1. Replace CSP-blocked inline style attributes and `element.style` progress updates with nonce-authorized stylesheet classes or semantic data attributes/classes for each of the six progress states.
2. Update the recovery-stage render path for `codes.length === 0` to show a clear message that previously issued recovery codes cannot be displayed after refresh and provide one prominent “Generate new recovery codes” action.
3. Prevent the “I have saved my codes” completion action from being displayed or enabled until recovery codes are currently available in the browser UI after a recovery-stage refresh.
4. Make the test mock outputs deterministic in a way that remains compatible with the security requirements, or explicitly implement a clearly isolated test/demo mode with predictable values while retaining cryptographically secure production behavior.

## DECISION

FAIL