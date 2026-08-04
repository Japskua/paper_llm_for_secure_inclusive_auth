## SUMMARY

The artifact is a strong single-file Bun/vanilla-JS implementation with TLS, CSRF protection, CSP nonces, opaque random reset tokens, token expiry, session binding, MFA simulation, rate limiting, Argon2id hashing, and safe client-side rendering. The primary defect is that client-side hash routes allow unauthenticated users to render the privacy and completion screens, including a false “Recovery complete” confirmation, without validating server-side recovery/acceptance state.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun server and browser application**
  - The complete server, HTML template, CSS, and browser JavaScript are contained in `app.ts`.
  - It uses Bun directly, has no bundler/framework/build step, and has no external assets or network calls.

- **PASS — TLS and security headers**
  - `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`.
  - Non-HTTPS requests are rejected.
  - HSTS, CSP with per-response nonce, `X-Content-Type-Options`, `X-Frame-Options`, restrictive referrer policy, permissions policy, no-cache headers, COOP, and CORP are set.

- **PASS — CSRF and session protections**
  - A cryptographically random server-side session and CSRF token are created.
  - The session cookie is `Secure`, `HttpOnly`, `SameSite=Strict`, and has a limited lifetime.
  - All POST API endpoints require the per-session `X-CSRF-Token`.
  - Reset records are bound to the session that requested them, preventing another session from using a captured token.

- **PASS — Reset-token security and recovery verification**
  - Reset tokens are generated with `randomBytes`, stored as SHA-256 hashes, are short-lived, and are invalidated after password reset.
  - Token verification checks session ownership, expiry, used status, and token structure.
  - Manual token submission is supported and the generated simulated reset link works in the requesting session.
  - The deterministic reset token and MFA code are logged in the browser as required for testing.

- **PASS — Password, MFA, and brute-force protections**
  - Passwords must have at least 12 characters and include uppercase, lowercase, numeric, and symbol characters.
  - Password values are hashed using Bun Argon2id and are not stored or logged in plaintext.
  - MFA is required after token verification and before password reset.
  - Recovery requests, invalid token attempts, and invalid MFA attempts are rate limited.

- **PASS — XSS/injection and external-request protections**
  - User-controlled values are not inserted with `innerHTML`; the UI uses `textContent` and DOM node construction.
  - The server does not reflect user-provided email, token, password, or code values into HTML.
  - The application has no outbound URL handling, redirects, or external fetches.
  - CSP disallows untrusted scripts and external resources.

- **FAIL — Protected confirmation/privacy flow integrity**
  - `route()` renders `renderPrivacy()` for `#privacy` and `renderSuccess()` for `#success` solely based on the browser URL fragment.
  - An unauthenticated visitor can directly navigate to `https://localhost:3000/#success` and see “Your password has been reset and the updated privacy statement has been accepted,” even though no reset or privacy acceptance occurred.
  - An unauthenticated visitor can also render the privacy-acceptance UI at `#privacy`. The POST is correctly rejected by the server, but the protected screen should not be presented as available before recovery.
  - This violates the requirement that internal confirmation screens function correctly and undermines clear, trustworthy security feedback.

- **FAIL — Notice styling helper is implemented incorrectly**
  - `el()` accepts only `(tag, text)`, but several calls pass a third `"notice"` argument:
    - `el("div", "...", "notice")`
  - The third argument is ignored, so the recovery, MFA, password-policy, and success notices do not receive the intended `.notice` class styling.
  - This is a UI implementation defect, though it does not affect the underlying security controls.

## FAILING_ITEMS

- Direct navigation to `#success` displays an unverified completion state without confirming that the password reset and privacy acceptance occurred in the current server-side session.
- Direct navigation to `#privacy` displays the privacy acceptance form before the user has completed recovery. Although the server blocks the mutation, the client route is not access-controlled.
- The `el()` helper ignores the intended CSS class supplied as a third argument, leaving multiple security/UX notices unstyled.

## NEW_TASKS

1. Add a server-side session-status endpoint, protected by the existing session cookie and returning only non-sensitive booleans such as `authenticated` and `privacyAccepted`.
2. Update client routing so `#privacy` is rendered only when the server confirms `authenticated === true`; otherwise route to the recovery screen with a clear message.
3. Update client routing so `#success` is rendered only when the server confirms both `authenticated === true` and `privacyAccepted === true`; otherwise route to the appropriate valid step and do not display a false completion message.
4. Update `el()` to accept an optional class name argument, or explicitly assign `.className = "notice"` after creating each notice element, so all intended notices receive the `.notice` styling.

## DECISION

FAIL