## SUMMARY

The artifact is a single-file Bun/TypeScript password recovery SPA with inline HTML, CSS, and vanilla browser JavaScript. It implements HTTPS, CSP nonces, server-side sessions and CSRF validation, random single-use reset tokens, Argon2id password hashing, throttling, MFA simulation, strong password policy, and a complete privacy-acceptance flow. The recovery link and manual token-entry paths function within the initiating browser session. No critical functional, security, compilation, or single-file compliance defects were identified.

## FUNCTIONAL_CHECK

- **Single `app.ts` file containing Bun server, HTML, CSS, and JavaScript: PASS**
  - The complete server implementation and client UI template are contained in the provided `app.ts`. There are no framework imports, bundlers, compilation steps, or external frontend assets.

- **Bun serves the application directly with TLS certificates: PASS**
  - `Bun.serve` is configured with `tls: { cert: Bun.file(CERT_PATH), key: Bun.file(KEY_PATH) }` using `certs/cert.pem` and `certs/key.pem`.
  - A separate HTTP listener redirects all plaintext requests to HTTPS using HTTP 308.

- **HTTPS and secure response headers: PASS**
  - HTTPS page responses include HSTS, CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, and `Cache-Control: no-store`.
  - API responses are also configured with restrictive security headers and no-store caching.

- **CSRF prevention on sensitive actions: PASS**
  - Each server-side session receives a cryptographically random CSRF token.
  - Every state-changing API endpoint requires and validates the `X-CSRF-Token` header.
  - The session cookie is `Secure`, `HttpOnly`, `SameSite=Strict`, and uses the `__Host-` prefix correctly.

- **Access control and workflow enforcement: PASS**
  - Reset-token verification is bound to the issuing session.
  - Password changes require recovery MFA verification.
  - Privacy acceptance requires successful password login plus sign-in MFA.
  - The protected SPA views query server-side workflow status before rendering privacy-sensitive confirmation content.

- **Password-reset token security: PASS**
  - Tokens use 32 bytes of cryptographic randomness (`randomHex(32)`).
  - Only a SHA-256 verifier is retained server-side; raw reset tokens are not stored.
  - Tokens expire after ten minutes.
  - Tokens are deleted immediately after successful verification, enforcing single use.
  - Invalid verification attempts are throttled.

- **Manual reset-token entry and verification-link flow: PASS**
  - The recovery UI provides a manual “Enter it manually” token path.
  - The academic simulated recovery link opens `/reset?token=...`.
  - The reset form pre-populates a valid query-string token and also permits manual entry.

- **Browser console mock delivery/testing values: PASS**
  - The server returns the academic testing token/MFA values only to the active session.
  - The browser client logs the recovery token and deterministic MFA codes through `console.log`.
  - The UI Logs panel mirrors those values for academic testing.

- **XSS/input handling: PASS**
  - Untrusted user values are not inserted through `innerHTML`.
  - The client uses `textContent`, `createElement`, and `replaceChildren`.
  - Contact, token, code, and password inputs are validated server-side.
  - The CSP allows only nonce-authorized application code and blocks external scripts, objects, frames, images, and external connections.

- **Password security and authentication controls: PASS**
  - Newly set passwords are hashed with `Bun.password.hash(..., { algorithm: "argon2id" })`.
  - Passwords are not stored in plaintext.
  - Password policy requires 14–128 characters with upper/lowercase letters, numbers, and symbols, and rejects spaces.
  - Login and recovery/MFA verification attempts are throttled.
  - Password login requires an additional MFA step before authentication is granted.

- **Phishing and social-engineering safety guidance: PASS**
  - Every major recovery/authentication view displays guidance not to share passwords, reset tokens, or MFA codes with staff or email messages.
  - The application does not implement outgoing redirects, remote fetches, or externally supplied URLs.

- **No external network calls: PASS**
  - Client fetches use only same-origin `/api/...` paths.
  - No third-party scripts, fonts, images, APIs, or assets are referenced.

- **Error handling and production disclosure: PASS**
  - Server exceptions return a generic `503 Service unavailable` response without stack traces or debug information.
  - User-facing failures use generic privacy-preserving messages where appropriate.

## FAILING_ITEMS

- None identified.

## NEW_TASKS

1. No remediation tasks required.

## DECISION

PASS