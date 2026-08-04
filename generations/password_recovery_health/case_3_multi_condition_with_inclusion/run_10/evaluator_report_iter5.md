## SUMMARY

The artifact is a well-structured single-file Bun HTTPS SPA with functional recovery, manual-code and verification-link paths, CSRF protection, throttling, security headers, CSP nonces, password-policy enforcement, MFA simulation, and ADHD-oriented guidance. However, it does not fully meet the security requirements because it embeds an initial account password in plaintext in `app.ts` before hashing it at startup. This violates the explicit requirement that passwords must never be stored in plaintext.

## FUNCTIONAL_CHECK

- **Single-file `app.ts`, Bun server, vanilla HTML/CSS/JS, no frameworks/build tools/external assets — PASS**
  - The server, page template, inline CSS, client JavaScript, and API logic are all in `app.ts`.
  - It uses Bun directly and does not reference frameworks, bundlers, package assets, or network resources.

- **HTTPS/TLS using provided certificates — PASS**
  - The server reads `certs/cert.pem` and `certs/key.pem` and configures `Bun.serve` with TLS.
  - HTTP-forwarded requests are rejected and HSTS is configured.

- **Password recovery flow is functional and supports both link and manual-code verification — PASS**
  - `/api/recovery-request` creates a random reset token and manual recovery code.
  - The client logs the simulated token/code delivery in the browser console and visible Logs panel.
  - The user can submit the manual recovery code or open `/verify?token=...` and verify using the link.
  - Verification advances to MFA, password replacement, login, and privacy confirmation.

- **All internal routes/links work — PASS**
  - The application serves `/`, `/recovery`, and `/verify`.
  - Verification URLs are generated only as internal `/verify?token=...` paths.
  - The client handles the token query parameter and offers link verification.

- **ADHD/inclusivity UX requirements — PASS**
  - The UI has visible progress, one-step-at-a-time instructions, calm language, clear “Next step” guidance, help content, and no unexpected redirects.
  - Only non-sensitive orientation state is retained in `localStorage`.
  - Users can restart and obtain a fresh recovery code without losing the high-level recovery reminder.

- **CSRF protection and sensitive-request protection — PASS**
  - A cryptographically random CSRF token is generated per server session.
  - Every sensitive `POST` route validates the session-bound CSRF token.
  - Session cookies are `Secure`, `HttpOnly`, `SameSite=Strict`, and scoped to the application path.

- **Access-control and IDOR protections — PASS**
  - Sensitive transitions are enforced through the server-side session stage.
  - Password changes require successful recovery verification and MFA in the same session.
  - Privacy confirmation requires an authenticated session.
  - Reset tokens are session-bound, preventing use of an intercepted token in an unrelated session.

- **Reset-token security — PASS**
  - Reset tokens use cryptographic randomness.
  - Tokens and manual codes expire after ten minutes.
  - Tokens are invalidated after successful verification and cannot be reused.
  - Password change also rechecks reset expiration.

- **XSS/input handling/CSP — PASS**
  - User input is validated server-side.
  - Client-generated dynamic content uses `textContent` and DOM APIs rather than unsafe HTML interpolation.
  - CSP uses a per-response nonce and blocks untrusted script sources.
  - No external scripts or third-party resources are loaded.

- **Security headers and production-style error behavior — PASS**
  - HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and no-cache headers are present.
  - Generic failure responses are used instead of stack traces or debug output.

- **Brute-force mitigation — PASS**
  - Recovery, verification, MFA, password, and login actions have per-action/per-identifier/per-source progressive retry delays.
  - Failure messages do not expose whether an account exists.

- **Strong password policy and password hashing — FAIL**
  - New passwords are validated for length and character diversity and are stored using bcrypt.
  - However, the initial password is embedded in plaintext in source code:
    ```ts
    const hash = await Bun.password.hash("HospitalDemo!2026", { algorithm: "bcrypt" });
    ```
  - This directly violates the requirement that passwords must be hashed using bcrypt or Argon2 and **never stored in plaintext**.

- **MFA implementation — PASS**
  - A separate MFA stage is required after recovery verification and before password replacement.
  - The fixed MFA value is acceptable for this explicitly deterministic mock environment, and it is only exposed after successful recovery verification.

- **No external network calls / no open redirects / phishing guidance — PASS**
  - The client only communicates with same-origin API endpoints.
  - Verification URLs are fixed internal URLs.
  - The help panel explicitly warns users never to share passwords or recovery codes with staff via email, phone, or messages.

## FAILING_ITEMS

- **A plaintext password is hardcoded in the server source.**
  - `HospitalDemo!2026` is present as a literal value in `app.ts`.
  - Hashing it during server initialization does not satisfy “never stored in plaintext,” because the source itself stores the plaintext credential.
  - This is both a credential-exposure risk and a direct failure of the password-storage requirement.

## NEW_TASKS

1. Replace the hardcoded plaintext password initialization with a pre-generated bcrypt password hash string, ensuring no plaintext account password appears anywhere in `app.ts`.
2. Verify that the replacement bcrypt hash is valid with `Bun.password.verify` and that the normal recovery flow can still reset the account password and complete login successfully.

## DECISION

**FAIL**