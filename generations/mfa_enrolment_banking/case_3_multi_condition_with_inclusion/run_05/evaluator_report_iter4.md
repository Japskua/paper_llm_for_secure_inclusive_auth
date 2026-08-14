## SUMMARY

The artifact is a single-file Bun SPA with substantial server-side security controls, TLS configuration, session handling, CSRF protection, rate limiting, encrypted OTP-secret storage, hashed recovery codes, responsive UI, and working simulated identity/TOTP setup flows. However, it does not fully meet the functional and inclusivity requirements: the custom QR encoder has a concrete format-information placement defect that can make generated QR codes unscannable, and the UI does not provide required reveal/hide/re-request affordances for sensitive setup and recovery material. The chosen primary font is also not clearly dyslexia-friendly.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no framework, build tool, compiler, or external assets**
  - `app.ts` contains the Bun server, HTML, CSS, and browser JavaScript. It imports only Bun’s built-in server API and makes no external network requests.

- **PASS — TLS is configured using the required certificate paths**
  - The server loads `certs/cert.pem` and `certs/key.pem` and passes them to `serve({ tls: { cert, key } })`.

- **PASS — Mobile-responsive SPA and generally legible layout**
  - The viewport tag, constrained `.shell`, scalable QR canvas, large inputs/buttons, spacing, and mobile-appropriate layout satisfy the responsive mobile-web requirement.

- **FAIL — QR-code provisioning option is reliable and functional**
  - The hand-written QR encoder has an error in its horizontal format-information placement:
    ```js
    else set(8,14-i-1,bit)
    ```
    For `i = 9`, this writes to column `4`, whereas the next required position is column `5`; subsequent bits are shifted and the final bit attempts to write at column `-1`. This produces invalid/malformed QR format information and can prevent authenticator apps from scanning the code.
  - A manual secret option exists, but that does not make a broken offered QR option acceptable.

- **PASS — Manual setup alternative is available**
  - The setup key is shown, copyable, and can be manually pasted into the optional “Manual setup key” field. The TOTP code can also be entered manually.

- **PASS — Simulated verification values are made available in browser console/UI**
  - Identity codes, current authenticator test OTPs, and recovery codes are emitted through browser-side `console.log`, as required for mock testing. The UI also displays the setup key and recovery codes.

- **PASS — Identity-code and TOTP verification work server-side**
  - Identity codes are generated securely, have expiry, are single-use, and are checked server-side.
  - TOTP activation validates the code from the server-generated secret with a limited clock-skew window and prevents reuse of accepted setup TOTP time steps.

- **PASS — Backup codes are cryptographically generated, stored hashed, and single-use**
  - Recovery codes use `crypto.getRandomValues`.
  - Only salted SHA-256 hashes are retained in account state.
  - Successfully submitted recovery codes are marked used.

- **PASS — Authorization and IDOR protections**
  - MFA account access is derived only from the server-side session cookie:
    ```ts
    const account = accounts.get(session.accountId);
    ```
  - No client-provided account/user identifier is accepted by MFA endpoints, preventing manipulated-account IDOR attempts.

- **PASS — CSRF protection is applied to state-changing authenticated endpoints**
  - State-changing authenticated endpoints check the session CSRF value through `X-CSRF-Token` or request body.
  - Sign-in uses a one-time bootstrap CSRF ticket.

- **PASS — Session security controls**
  - Session IDs are cryptographically random.
  - The session cookie is `HttpOnly`, `Secure`, `SameSite=Strict`, scoped to `/`, and has a maximum age.
  - Idle and absolute timeouts are enforced.
  - A new session is created at sign-in, and logout invalidates the server-side session and expires the cookie.

- **PASS — Security headers and restrictive CORS**
  - CSP with per-page nonce, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, no-cache controls, referrer policy, and permissions policy are present.
  - CORS only reflects approved localhost/loopback HTTPS origins.

- **PASS — Input validation and safe rendering**
  - JSON body size is limited and parsed defensively.
  - Email, OTP, and recovery-code formats are validated.
  - Client rendering uses DOM APIs and `textContent`, not unsafe `innerHTML`, avoiding reflected/DOM XSS from displayed API data.

- **PASS — Rate limiting and lockout**
  - Sign-in, identity verification, authenticator setup confirmation, and recovery-code submission all enforce repeated-failure lockouts.

- **FAIL — Required retry/re-request/reveal/hide UX is incomplete**
  - The requirements explicitly call for users to be able to “retry any step or reveal, hide and re-request codes without penalty.”
  - Setup secrets and recovery codes are always fully visible once rendered; there is no hide/reveal control.
  - Identity-code re-requesting retains prior failure attempts via:
    ```ts
    newVerificationPreservingState(account.identity)
    ```
    and re-requesting is refused once the identity record is locked. This is not a clear “re-request without penalty” experience.
  - There is no user-facing recovery-code-entry flow, even though the server has `/api/recovery/use`. The only recovery-code UI is display/copy/regeneration.

- **FAIL — Dyslexia-friendly typeface requirement is not clearly met**
  - The font stack starts with `Arial`:
    ```css
    font-family:Arial,"Atkinson Hyperlegible","Segoe UI",sans-serif
    ```
  - Since Arial will normally be available, `Atkinson Hyperlegible` will not be used. Arial is legible but is not a specifically dyslexia-friendly choice. The app should prioritize an appropriate installed dyslexia-accessible font stack such as `Atkinson Hyperlegible`, `OpenDyslexic` where available, Verdana, or a similarly spacious fallback.

- **PASS — Clear language, examples, accessible labels, and non-moving UI**
  - Instructions are concise, code examples are supplied, controls have labels, help is available with `<details>`, and there are no animations, timers, flashing content, or reading time limits.

## FAILING_ITEMS

- The custom QR generator writes QR format bits to incorrect coordinates, including an out-of-bounds final coordinate. The QR provisioning code may not scan successfully in authenticator applications.
- The UI lacks hide/reveal controls for the authenticator setup key and recovery codes, despite the explicit inclusivity requirement.
- Re-requesting an identity code carries forward failed-code attempts and is blocked during lockout, which conflicts with the requested ability to re-request codes without penalty.
- The server supports recovery-code use, but the SPA exposes no recovery-code submission screen or route for a user to actually use a saved recovery code.
- The font stack prioritizes Arial over the dyslexia-friendly fallback, so the intended accessible typeface is not normally used.

## NEW_TASKS

1. Replace or correct the custom QR-code implementation and validate generated `otpauth://` codes with a real QR decoder/authenticator app; preferably use a tested, self-contained QR implementation embedded in `app.ts`.
2. Add accessible “Hide setup key” / “Show setup key” and “Hide recovery codes” / “Show recovery codes” controls, with hidden content removed or masked from the visible UI until explicitly revealed.
3. Adjust identity-code re-request behavior so requesting a fresh code is always available and clearly explained; keep brute-force verification protections while avoiding carried-over penalties for a newly issued code where compatible with the security model.
4. Add a user-facing recovery-code entry screen, reachable from the MFA settings or an internal recovery route, which submits to `/api/recovery/use`, displays specific errors, and confirms one-time use on success.
5. Change the font stack to prioritize a dyslexia-accessible font before Arial, with robust system fallbacks and the existing letter/line spacing retained.

## DECISION

**FAIL**